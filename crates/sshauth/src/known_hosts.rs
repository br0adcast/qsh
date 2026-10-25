//! The client's record of which server key belongs to which host.
//!
//! Trust on first use, exactly as SSH does it: the first key seen for a host
//! is shown to the user and pinned; a key that changes afterwards is refused
//! loudly rather than trusted quietly -- that case is either a reinstalled
//! server or an attacker, and the two are indistinguishable from here.
//!
//! Every write (`pin`) writes and syncs a complete sibling temporary file,
//! then atomically renames it over the configured entry. On Unix new files
//! are `0600`; validated existing public pin files may also be readable by
//! others. Reads and publication validate the observed route and authority.
//! Failed cleanup removes only the exact created temporary inode still at
//! its owned name. Unknown/moved names are retained, and temporary files
//! never grant trust. This does not add directory-fsync crash durability or
//! an atomic snapshot against concurrent edits by root/the same UID.
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
#[cfg(any(test, not(unix)))]
use std::fs;
#[cfg(test)]
use std::fs::File;
#[cfg(any(test, not(unix)))]
use std::fs::OpenOptions;
#[cfg(any(test, not(unix)))]
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use transport::auth::AuthError;

#[cfg(unix)]
mod storage;

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

/// Require a host identifier that round-trips through the pin store's record
/// syntax. This is not DNS/IDNA validation; safe opaque identifiers are allowed.
/// Rejection never echoes the caller's potentially hostile host text.
pub fn validate_host_identifier(host: &str) -> Result<(), AuthError> {
    if host.is_empty()
        || host.starts_with('#')
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AuthError::Backend(
            "host identifier must be nonempty, not start with #, and contain no whitespace or control characters".into(),
        ));
    }
    Ok(())
}

/// One parsed `host port base64-key` line.
struct Entry {
    host: String,
    port: u16,
    key: [u8; 32],
}

#[derive(Clone, Copy)]
enum HostIdentity<'a> {
    Ip(IpAddr),
    Scoped(Ipv6Addr, &'a str),
    Dns(&'a str),
    Opaque(&'a str),
}

impl<'a> HostIdentity<'a> {
    fn of(host: &'a str) -> Self {
        if let Ok(ip) = host.parse() {
            return Self::Ip(ip);
        }
        if let Some((address, zone)) = host.split_once('%') {
            if !zone.is_empty() && !zone.contains('%') {
                if let Ok(address) = address.parse() {
                    return Self::Scoped(address, zone);
                }
            }
        }
        // Recognize ordinary ASCII DNS labels only. The original trailing dot
        // stays in the comparison: absolute and search-list lookup can differ.
        let labels = host.strip_suffix('.').unwrap_or(host);
        let dns = !labels.is_empty()
            && labels.len() <= 253
            && labels.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if dns {
            Self::Dns(host)
        } else {
            Self::Opaque(host)
        }
    }

    fn matches(self, other: Self) -> bool {
        match (self, other) {
            (Self::Ip(a), Self::Ip(b)) => a == b,
            (Self::Scoped(a, az), Self::Scoped(b, bz)) => a == b && az == bz,
            (Self::Dns(a), Self::Dns(b)) => a.eq_ignore_ascii_case(b),
            (Self::Opaque(a), Self::Opaque(b)) => a == b,
            _ => false,
        }
    }
}

fn pinned_key<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    host: &str,
    port: u16,
) -> Result<Option<[u8; 32]>, AuthError> {
    let identity = HostIdentity::of(host);
    let mut pinned = None;
    for entry in entries {
        if entry.port == port && identity.matches(HostIdentity::of(&entry.host)) {
            if pinned.is_some_and(|seen| seen != entry.key) {
                return Err(AuthError::Backend(
                    "conflicting keys in equivalent QSH host-pin records; inspect the pin store and remove stale entries".into(),
                ));
            }
            pinned = Some(entry.key);
        }
    }
    Ok(pinned)
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
    validate_host_identifier(host).ok()?;
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

/// Original text with spans only for records accepted by the trust parser.
/// Unknown lines remain text, never entries used for lookup.
struct Document {
    text: String,
    records: Vec<(Entry, std::ops::Range<usize>)>,
}

impl Document {
    fn parse(text: String) -> Self {
        let mut offset = 0;
        let records = text
            .split_inclusive('\n')
            .filter_map(|line| {
                let range = offset..offset + line.len();
                offset = range.end;
                parse_line(line).map(|entry| (entry, range))
            })
            .collect();
        Self { text, records }
    }

    fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.records.iter().map(|(entry, _)| entry)
    }

    /// Remove only parsed exact-target records, then append a canonical pin.
    /// Retained bytes keep their line endings; an unterminated tail needs one
    /// separator so appending cannot turn its text into part of the new record.
    fn with_pin(&self, host: &str, port: u16, key: &[u8; 32]) -> String {
        let mut contents = String::with_capacity(self.text.len());
        let mut offset = 0;
        for (entry, range) in &self.records {
            if entry.host == host && entry.port == port {
                contents.push_str(&self.text[offset..range.start]);
                offset = range.end;
            }
        }
        contents.push_str(&self.text[offset..]);
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push('\n');
        }
        contents.push_str(&format!("{host} {port} {}\n", BASE64.encode(key)));
        contents
    }
}

/// The known-hosts file: `host port base64-key`, one entry per line, `#`
/// comments and blank lines ignored -- the same shape as OpenSSH's own file.
/// Lookup folds ordinary ASCII DNS letter case and compares strict IP literals
/// by value within their family. Trailing-dot presence and IPv6 zone text stay
/// significant. Unicode and other safe opaque identifiers match exactly; no
/// IDNA, resolver or interface lookup is performed. Stored spelling is retained.
/// Port equality is exact, and prefixes/suffixes never match another host.
pub struct KnownHosts {
    path: PathBuf,
}

struct LoadedDocument {
    document: Document,
    #[cfg(unix)]
    binding: storage::ReadBinding,
}
impl LoadedDocument {
    fn validate(&self) -> Result<(), AuthError> {
        #[cfg(unix)]
        self.binding.validate().map_err(|error| {
            AuthError::Backend(format!("checking QSH pin-store authority: {error}"))
        })?;
        Ok(())
    }
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
    #[cfg(unix)]
    fn read_entries(&self) -> Result<LoadedDocument, AuthError> {
        let (text, binding) = storage::read(&self.path)
            .map_err(|error| {
                AuthError::Backend(format!("reading {}: {error}", self.path.display()))
            })?
            .into_parts();
        Ok(LoadedDocument {
            document: Document::parse(text),
            binding,
        })
    }

    #[cfg(not(unix))]
    fn read_entries(&self) -> Result<LoadedDocument, AuthError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(LoadedDocument {
                document: Document::parse(text),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LoadedDocument {
                document: Document::parse(String::new()),
            }),
            Err(e) => Err(AuthError::Backend(format!(
                "reading {}: {e}",
                self.path.display()
            ))),
        }
    }

    /// What we know about `host:port`'s key. Every equivalent entry must agree;
    /// conflicting keys, including exact duplicate spellings, are an error.
    /// A manual correction must remove stale rows instead of appending a new
    /// winner. A single existing key still produces Known or Changed normally.
    pub fn check(&self, host: &str, port: u16, key: &[u8; 32]) -> Result<HostVerdict, AuthError> {
        validate_host_identifier(host)?;
        let entries = self.read_entries()?;
        let pinned = pinned_key(entries.document.entries(), host, port)?;
        entries.validate()?;
        match pinned {
            None => Ok(HostVerdict::Unknown),
            Some(pinned) if &pinned == key => Ok(HostVerdict::Known),
            Some(pinned) => Ok(HostVerdict::Changed { pinned }),
        }
    }

    /// Record `key` as this host's key. The caller has already shown the
    /// fingerprint and got a yes -- this function does not ask.
    ///
    /// An unambiguous exact spelling can be replaced. An equivalent same-key
    /// entry is a no-op; replacing a different spelling or conflicting records
    /// is refused for manual repair, never migrated behind the caller's back.
    ///
    /// Holds [`PinLock`] for the whole read-modify-write-rename, so a
    /// concurrent `pin` (even for a different host) waits instead of
    /// racing -- see the module doc-comment.
    pub fn pin(&self, host: &str, port: u16, key: &[u8; 32]) -> Result<(), AuthError> {
        validate_host_identifier(host)?;
        let mut lock = PinLock::acquire(&self.path)?;

        let entries = self.read_locked(&lock)?;
        if let Some(pinned) = pinned_key(entries.document.entries(), host, port)? {
            if &pinned == key {
                Self::validate_locked(&lock, &entries)?;
                return Ok(());
            }
            let identity = HostIdentity::of(host);
            if entries.document.entries().any(|entry| {
                entry.port == port
                    && entry.host != host
                    && identity.matches(HostIdentity::of(&entry.host))
            }) {
                return Err(AuthError::Backend(
                    "conflicting replacement would rewrite equivalent QSH host aliases; remove stale entries manually".into(),
                ));
            }
        }
        Self::validate_locked(&lock, &entries)?;
        self.write_locked(
            &mut lock,
            &entries,
            entries.document.with_pin(host, port, key).as_bytes(),
        )
        // The single transaction lock is released here, after the rename
        // has already made the new contents visible.
    }

    /// Record `key` as this host's key ONLY if nothing is pinned for it yet,
    /// and say what was on file before: `Unknown` means it is pinned now;
    /// `Known` and `Changed` mean the file was left exactly as it was.
    ///
    /// For a key authenticated by a completed handshake or reported by a
    /// verified SSH bootstrap, where an existing line, even a
    /// stale one, is for a person to remove, not for this call to replace.
    /// The check and the write happen under one [`PinLock`], so another
    /// process pinning this host in between cannot be overwritten.
    pub fn pin_if_absent(
        &self,
        host: &str,
        port: u16,
        key: &[u8; 32],
    ) -> Result<HostVerdict, AuthError> {
        validate_host_identifier(host)?;
        let mut lock = PinLock::acquire(&self.path)?;

        let entries = self.read_locked(&lock)?;
        if let Some(pinned) = pinned_key(entries.document.entries(), host, port)? {
            Self::validate_locked(&lock, &entries)?;
            return Ok(if &pinned == key {
                HostVerdict::Known
            } else {
                HostVerdict::Changed { pinned }
            });
        }
        Self::validate_locked(&lock, &entries)?;
        self.write_locked(
            &mut lock,
            &entries,
            entries.document.with_pin(host, port, key).as_bytes(),
        )?;
        Ok(HostVerdict::Unknown)
    }

    /// Where the store lives, for a line that tells a person which file to
    /// edit.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_locked(&self, lock: &PinLock) -> Result<LoadedDocument, AuthError> {
        #[cfg(unix)]
        {
            let (text, binding) = lock.transaction.read().map_err(storage_error)?.into_parts();
            Ok(LoadedDocument {
                document: Document::parse(text),
                binding,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = lock;
            self.read_entries()
        }
    }

    fn validate_locked(lock: &PinLock, entries: &LoadedDocument) -> Result<(), AuthError> {
        #[cfg(unix)]
        {
            lock.transaction
                .validate(&entries.binding)
                .map_err(storage_error)
        }
        #[cfg(not(unix))]
        {
            let _ = lock;
            entries.validate()
        }
    }

    fn write_locked(
        &self,
        lock: &mut PinLock,
        entries: &LoadedDocument,
        contents: &[u8],
    ) -> Result<(), AuthError> {
        #[cfg(unix)]
        {
            lock.transaction
                .replace(&entries.binding, contents)
                .map_err(storage_error)
        }
        #[cfg(not(unix))]
        {
            let _ = (lock, entries);
            self.write_atomic(contents)
        }
    }

    #[cfg(not(unix))]
    fn write_atomic(&self, contents: &[u8]) -> Result<(), AuthError> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)
                .map_err(|e| AuthError::Backend(format!("creating {}: {e}", dir.display())))?;
        }
        let tmp_path = temp_path_for(&self.path);
        // A collision is never ours. This backend has no qualified inode/name
        // identity check for failed cleanup, so retain rather than guess.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(storage_error)?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(storage_error)?;
        drop(file);
        fs::rename(&tmp_path, &self.path).map_err(storage_error)
    }
}

fn storage_error(error: std::io::Error) -> AuthError {
    AuthError::Backend(format!("QSH pin-store transaction: {error}"))
}
fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("known_hosts");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!(".{name}.tmp.{}.{nanos}", std::process::id()))
}

/// An advisory lock held across `pin`'s whole read-modify-write-rename --
/// see the module doc-comment for why it exists and why it lives on a
/// SIBLING file rather than `self.path`.
///
/// Unix only: one retained transaction owns the actual flock. Other targets
/// get a no-op lock (the
/// same reach as the rest of this module's Unix-specific hardening, e.g.
/// owner-only permissions).
#[cfg(unix)]
struct PinLock {
    transaction: storage::Transaction,
}

#[cfg(not(unix))]
struct PinLock;

#[cfg(unix)]
impl PinLock {
    fn acquire(path: &Path) -> Result<Self, AuthError> {
        Ok(Self {
            transaction: storage::Transaction::acquire(path).map_err(storage_error)?,
        })
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
    #[cfg(unix)]
    include!("known_hosts/authority_tests.rs");

    fn private_test_dir() -> std::io::Result<tempfile::TempDir> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
        }
        #[cfg(not(unix))]
        tempfile::tempdir()
    }

    fn write_test_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
                .write_all(contents.as_ref())
        }
        #[cfg(not(unix))]
        fs::write(path, contents)
    }

    fn base64_key(key: &[u8; 32]) -> String {
        BASE64.encode(key)
    }

    #[test]
    fn pin_insertion_preserves_original_text_and_newline_boundaries() {
        for if_absent in [false, true] {
            for tail in [
                "EMPTY",
                "",
                "# comment\n\nunknown record\n",
                "# comment\r\n\r\nunknown record\r\n",
                "# unterminated",
            ] {
                let dir = private_test_dir().unwrap();
                let path = dir.path().join("known_hosts");
                let original = if tail == "EMPTY" {
                    String::new()
                } else {
                    format!(
                        "  other.example\t22\t{} annotation\r\n{tail}",
                        base64_key(&[1; 32])
                    )
                };
                write_test_file(&path, &original).unwrap();
                let hosts = KnownHosts::open(path.clone());
                if if_absent {
                    assert_eq!(
                        hosts.pin_if_absent("new.example", 22, &[2; 32]).unwrap(),
                        HostVerdict::Unknown
                    );
                } else {
                    hosts.pin("new.example", 22, &[2; 32]).unwrap();
                }
                let separator = if original.is_empty() || original.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                assert_eq!(
                    fs::read(&path).unwrap(),
                    format!(
                        "{original}{separator}new.example 22 {}\n",
                        base64_key(&[2; 32])
                    )
                    .as_bytes()
                );
                assert_eq!(
                    hosts.check("other.example", 22, &[1; 32]).unwrap(),
                    if original.is_empty() {
                        HostVerdict::Unknown
                    } else {
                        HostVerdict::Known
                    }
                );
                assert_eq!(
                    hosts.check("new.example", 22, &[2; 32]).unwrap(),
                    HostVerdict::Known
                );
            }
        }
    }

    #[test]
    fn pin_replacement_preserves_unrelated_records_and_text() {
        let dir = private_test_dir().unwrap();
        let path = dir.path().join("known_hosts");
        let original = format!("# header\r\ntarget.example 22 {}\r\n\nunknown record\n  other.example 22 {} trailing\r\ntarget.example bad-port invalid\ntarget.example 22 {}\n# tail", base64_key(&[1; 32]), base64_key(&[3; 32]), base64_key(&[1; 32]));
        write_test_file(&path, original).unwrap();
        let hosts = KnownHosts::open(path.clone());
        hosts.pin("target.example", 22, &[2; 32]).unwrap();
        let expected = format!("# header\r\n\nunknown record\n  other.example 22 {} trailing\r\ntarget.example bad-port invalid\n# tail\ntarget.example 22 {}\n", base64_key(&[3; 32]), base64_key(&[2; 32]));
        assert_eq!(fs::read(&path).unwrap(), expected.as_bytes());
        assert_eq!(
            hosts.check("target.example", 22, &[2; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    #[test]
    fn pin_no_op_preserves_original_bytes() {
        let dir = private_test_dir().unwrap();
        let path = dir.path().join("known_hosts");
        let original = format!(
            "# header\r\n\r\n  Example.org\t22 {} trailing\r\nExample.org 22 {}\nunknown record",
            base64_key(&[1; 32]),
            base64_key(&[1; 32])
        );
        write_test_file(&path, &original).unwrap();
        let hosts = KnownHosts::open(path.clone());
        for host in ["Example.org", "example.org"] {
            hosts.pin(host, 22, &[1; 32]).unwrap();
            assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
            assert_eq!(
                hosts.pin_if_absent(host, 22, &[1; 32]).unwrap(),
                HostVerdict::Known
            );
            assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
            assert_eq!(
                hosts.pin_if_absent(host, 22, &[2; 32]).unwrap(),
                HostVerdict::Changed { pinned: [1; 32] }
            );
            assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
        }
    }

    #[test]
    fn preserved_malformed_records_never_grant_trust() {
        let dir = private_test_dir().unwrap();
        let path = dir.path().join("known_hosts");
        let original = format!("target.example bad {}\ntarget.example 22 !invalid!\ntarget.example 22 YQ==\n#target.example 22 {}\n", base64_key(&[1; 32]), base64_key(&[1; 32]));
        write_test_file(&path, &original).unwrap();
        let hosts = KnownHosts::open(path.clone());
        assert_eq!(
            hosts.check("target.example", 22, &[1; 32]).unwrap(),
            HostVerdict::Unknown
        );
        assert_eq!(
            hosts.pin_if_absent("target.example", 22, &[2; 32]).unwrap(),
            HostVerdict::Unknown
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            format!("{original}target.example 22 {}\n", base64_key(&[2; 32])).as_bytes()
        );
        assert_eq!(
            hosts.check("target.example", 22, &[2; 32]).unwrap(),
            HostVerdict::Known
        );
        write_test_file(&path, [0xff, b'\n']).unwrap();
        assert!(hosts.check("target.example", 22, &[2; 32]).is_err());
        assert!(hosts.pin("target.example", 22, &[2; 32]).is_err());
        assert!(hosts.pin_if_absent("target.example", 22, &[2; 32]).is_err());
        assert_eq!(fs::read(&path).unwrap(), [0xff, b'\n']);
    }

    fn rejects_injected_pin(if_absent: bool) {
        let dir = private_test_dir().unwrap();
        let path = dir.path().join("known_hosts");
        let hosts = KnownHosts::open(path.clone());
        hosts.pin("sentinel.example", 60022, &[1; 32]).unwrap();
        let before = fs::read(&path).unwrap();
        // Fixed public pin bytes, not a private key or an account credential.
        let injected = format!("prefix\nvictim.example 60022 {}\n#", base64_key(&[7; 32]));
        let result = if if_absent {
            hosts.pin_if_absent(&injected, 60022, &[9; 32]).map(|_| ())
        } else {
            hosts.pin(&injected, 60022, &[9; 32])
        };
        let victim = hosts.check("victim.example", 60022, &[7; 32]).unwrap();
        let changed = fs::read(&path).unwrap() != before;
        assert!(
            result.is_err() && !changed && victim == HostVerdict::Unknown,
            "unsafe pin accepted={}, store changed={changed}, injected victim={victim:?}",
            result.is_ok()
        );
    }

    #[test]
    fn pin_host_identifier_cannot_inject_a_trusted_record() {
        rejects_injected_pin(false);
    }

    #[test]
    fn pin_host_identifier_if_absent_cannot_inject_a_trusted_record() {
        rejects_injected_pin(true);
    }

    #[test]
    fn pin_host_identifiers_are_rejected_before_any_filesystem_side_effect() {
        let mut invalid: Vec<String> = [
            "",
            "#comment",
            "two words",
            "a\u{a0}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        invalid.extend(
            (0..=32)
                .chain(127..=159)
                .map(|code| format!("a{}b", char::from_u32(code).unwrap())),
        );
        for host in invalid {
            for operation in 0..3 {
                let dir = private_test_dir().unwrap();
                let parent = dir.path().join("absent");
                let hosts = KnownHosts::open(parent.join("known_hosts"));
                let result = match operation {
                    0 => hosts.check(&host, 60022, &[1; 32]).map(|_| ()),
                    1 => hosts.pin(&host, 60022, &[1; 32]),
                    _ => hosts.pin_if_absent(&host, 60022, &[1; 32]).map(|_| ()),
                };
                assert!(result.is_err(), "operation {operation} accepted {host:?}");
                assert!(!parent.exists(), "invalid identifier created store state");
            }
        }
    }

    #[test]
    fn pin_host_lookup_equivalence_is_conservative() {
        for (stored, query, same) in [
            ("Example.ORG", "example.org", true),
            ("Example.ORG.", "example.org.", true),
            ("example.org", "example.org.", false),
            ("host", "HOST", true),
            ("host", "host.", false),
            ("2001:DB8::1", "2001:db8:0:0:0:0:0:1", true),
            ("fe80::a%eth0", "FE80:0:0:0:0:0:0:a%eth0", true),
            ("fe80::a%eth0", "fe80::a%ETH0", false),
            ("fe80::a%2", "fe80::a%02", false),
            ("fe80::a%2", "fe80::a%eth0", false),
            ("fe80::a%2", "fe80::a", false),
            ("192.0.2.1", "::ffff:192.0.2.1", false),
            ("192.0.2.1", "192.0.2.01", false),
            ("2001:db8::1", "[2001:db8::1]", false),
            ("HOST_NAME", "host_name", false),
            ("Bücher.example", "bücher.example", false),
            ("bücher.example", "xn--bcher-kva.example", false),
            ("XN--BCHER-KVA.example", "xn--bcher-kva.EXAMPLE", true),
            ("opaque,token", "opaque,token", true),
            ("opaque,token", "OPAQUE,token", false),
            ("name#tag", "name#tag", true),
            ("name#tag", "NAME#tag", false),
        ] {
            let dir = private_test_dir().unwrap();
            let path = dir.path().join("known_hosts");
            let hosts = KnownHosts::open(path.clone());
            hosts.pin(stored, 60022, &[1; 32]).unwrap();
            let before = fs::read(&path).unwrap();
            let expected = if same {
                HostVerdict::Known
            } else {
                HostVerdict::Unknown
            };
            assert_eq!(
                hosts.check(query, 60022, &[1; 32]).unwrap(),
                expected,
                "{stored:?} vs {query:?}"
            );
            assert_eq!(
                hosts.check(query, 60023, &[1; 32]).unwrap(),
                HostVerdict::Unknown
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "lookup must not migrate spelling"
            );
            if same {
                assert_eq!(
                    hosts.pin_if_absent(query, 60022, &[2; 32]).unwrap(),
                    HostVerdict::Changed { pinned: [1; 32] }
                );
                hosts.pin(query, 60022, &[1; 32]).unwrap();
                assert_eq!(
                    fs::read(&path).unwrap(),
                    before,
                    "same-key alias is a byte-preserving no-op"
                );
            }
        }
    }

    #[test]
    fn pin_host_conflicting_duplicate_or_equivalent_records_are_ambiguous() {
        for (first, second) in [
            ("same.example", "same.example"),
            ("Example.org", "example.ORG"),
            ("2001:DB8::1", "2001:db8:0:0::1"),
            ("fe80::a%eth0", "FE80:0:0:0:0:0:0:a%eth0"),
        ] {
            for reverse in [false, true] {
                let dir = private_test_dir().unwrap();
                let path = dir.path().join("known_hosts");
                let keys = if reverse {
                    [[2; 32], [1; 32]]
                } else {
                    [[1; 32], [2; 32]]
                };
                let before = format!(
                    "{first} 60022 {}\n{second} 60022 {}\nother.example 60022 {}\n",
                    base64_key(&keys[0]),
                    base64_key(&keys[1]),
                    base64_key(&[9; 32])
                );
                write_test_file(&path, &before).unwrap();
                let hosts = KnownHosts::open(path.clone());
                for query in [first, second] {
                    for offered in [[1; 32], [2; 32], [3; 32]] {
                        let outcomes = [
                            hosts.check(query, 60022, &offered).map(|_| ()),
                            hosts.pin_if_absent(query, 60022, &offered).map(|_| ()),
                            hosts.pin(query, 60022, &offered),
                        ];
                        for outcome in outcomes {
                            assert!(outcome.is_err(), "ambiguous pin selected a key for {query}");
                            assert!(outcome.unwrap_err().to_string().contains("conflicting"));
                        }
                        assert_eq!(fs::read(&path).unwrap(), before.as_bytes());
                    }
                }
                assert_eq!(
                    hosts.check("other.example", 60022, &[9; 32]).unwrap(),
                    HostVerdict::Known
                );
            }
        }
    }

    #[test]
    fn pin_host_same_key_aliases_are_known_but_cross_alias_replacement_is_refused() {
        for duplicate in [false, true] {
            let dir = private_test_dir().unwrap();
            let path = dir.path().join("known_hosts");
            let mut before = format!("Example.org 60022 {}\n", base64_key(&[1; 32]));
            if duplicate {
                before.push_str(&format!("example.ORG 60022 {}\n", base64_key(&[1; 32])));
            }
            write_test_file(&path, &before).unwrap();
            let hosts = KnownHosts::open(path.clone());
            assert_eq!(
                hosts.check("EXAMPLE.ORG", 60022, &[1; 32]).unwrap(),
                HostVerdict::Known
            );
            assert_eq!(
                hosts.pin_if_absent("example.org", 60022, &[2; 32]).unwrap(),
                HostVerdict::Changed { pinned: [1; 32] }
            );
            hosts.pin("example.org", 60022, &[1; 32]).unwrap();
            assert!(hosts.pin("example.org", 60022, &[2; 32]).is_err());
            assert_eq!(fs::read(&path).unwrap(), before.as_bytes());
            if duplicate {
                assert!(hosts.pin("Example.org", 60022, &[2; 32]).is_err());
                assert_eq!(fs::read(&path).unwrap(), before.as_bytes());
            } else {
                hosts.pin("Example.org", 60022, &[2; 32]).unwrap();
                assert_eq!(
                    hosts.check("EXAMPLE.ORG", 60022, &[2; 32]).unwrap(),
                    HostVerdict::Known
                );
            }
        }
    }

    #[test]
    fn pin_host_equivalent_first_pins_race_without_creating_conflicting_records() {
        let dir = private_test_dir().unwrap();
        let path = dir.path().join("known_hosts");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers = [("Race.Example", [1; 32]), ("race.example", [2; 32])].map(|(host, key)| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                KnownHosts::open(path).pin_if_absent(host, 60022, &key)
            })
        });
        barrier.wait();
        let [first, second] = workers;
        let outcomes = [first.join(), second.join()];
        let outcomes = outcomes.map(|result| result.unwrap().unwrap());
        assert_eq!(
            outcomes
                .iter()
                .filter(|v| **v == HostVerdict::Unknown)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|v| matches!(v, HostVerdict::Changed { .. }))
                .count(),
            1
        );
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        let winner = match outcomes {
            [HostVerdict::Unknown, HostVerdict::Changed { pinned }] => {
                assert_eq!(pinned, [1; 32]);
                pinned
            }
            [HostVerdict::Changed { pinned }, HostVerdict::Unknown] => {
                assert_eq!(pinned, [2; 32]);
                pinned
            }
            _ => panic!("one unambiguous first pin required"),
        };
        assert_eq!(
            KnownHosts::open(path)
                .check("RACE.EXAMPLE", 60022, &winner)
                .unwrap(),
            HostVerdict::Known
        );
    }

    #[test]
    fn an_unknown_host_is_reported_as_unknown_then_pinned() {
        let dir = private_test_dir().expect("tempdir");
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
        let dir = private_test_dir().expect("tempdir");
        let hosts = KnownHosts::open(dir.path().join("known_hosts"));
        hosts.pin("example.org", 60022, &[1u8; 32]).expect("pin");
        match hosts.check("example.org", 60022, &[2u8; 32]).unwrap() {
            HostVerdict::Changed { pinned } => assert_eq!(pinned, [1u8; 32]),
            other => panic!("expected a changed-key verdict, got {other:?}"),
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let dir = private_test_dir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        write_test_file(
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
        let dir = private_test_dir().expect("tempdir");
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
        let dir = private_test_dir().expect("tempdir");
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
        let dir = private_test_dir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        write_test_file(
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
        let dir = private_test_dir().expect("tempdir");
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
        let dir = private_test_dir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let hosts = KnownHosts::open(path.clone());
        hosts
            .pin("a.example.org", 60022, &[1u8; 32])
            .expect("pin a");

        let original = format!(
            "# retained header\r\n{}\nunknown record\n",
            fs::read_to_string(&path).unwrap()
        );
        write_test_file(&path, &original).unwrap();

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
        assert_eq!(
            fs::read(&path).unwrap(),
            format!("{original}b.example.org 60022 {}\n", base64_key(&[2; 32])).as_bytes()
        );

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
        let dir = private_test_dir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let lock_path = dir.path().join(".known_hosts.lock");
        let elsewhere = dir.path().join("elsewhere");
        write_test_file(&elsewhere, b"").expect("write the symlink's target");
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
        let dir = private_test_dir().expect("tempdir");
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

        let dir = private_test_dir().expect("tempdir");
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
