//! Version/build/checksum of the `qshd` executable -- shared by both
//! daemon paths (used to belong to the now-removed qsh path too, kept for
//! the new transport): `version::reconcile` and the `ensure`/
//! `transport-ensure` client use them to compare a live daemon against the
//! executable that was just uploaded.
//!
//! The persistent certificate/mTLS half of this module (the qsh path) was
//! removed -- the new transport trusts via Noise keys instead of DER
//! certificates, held IN-MEMORY ONLY as `transport_daemon::SharedAllowlist`
//! (the on-disk `transport_state.rs` counterpart was itself retired: a
//! live, self-cleaning allowlist has no durable copy to keep in sync).

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Chunk size for [`hash_file_streaming`]'s read loop. 64 KiB: large enough
/// that the number of syscalls stays small for a tens-of-MB executable,
/// small enough that this never approaches the 73.5 MB whole-file
/// allocation it replaces.
const HASH_CHUNK_SIZE: usize = 64 * 1024;

/// Sha256 of the file at `path`, read in fixed-size chunks and fed to the
/// hasher incrementally, rather than reading the whole file into one
/// `Vec<u8>` first. Produces the exact same hex string as hashing a
/// whole-buffer read of the same bytes -- streaming changes how the bytes
/// are delivered to the hasher, not what they are, and SHA-256 is defined
/// over the byte stream regardless of how it is chunked (see the
/// `streaming_hash_matches_whole_buffer_hash_*` tests below for the
/// property, checked across several lengths straddling the chunk boundary).
/// Split out from [`self_checksum`] so it can be exercised against an
/// arbitrary fixture file in tests -- `self_checksum` itself only ever
/// calls it with the path from [`self_exe_path`].
fn hash_file_streaming(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_CHUNK_SIZE];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Protocol/executable version of `qshd` -- goes into `TRANSPORT-READY`
/// and into the `STATUS` response so the client can check compatibility.
pub const QSHD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The environment variable a DEBUG build -- or one built with the
/// `test-build-labels` feature, for measurements -- takes its build label
/// from, keyed by its own checksum: `<sha256 hex>=<label>[,<sha256
/// hex>=<label>...]`. It exists so an end-to-end test can hand a daemon "a
/// newer build" that is the same code with a few bytes appended, without
/// building qshd twice; a release build without that feature (every binary a
/// client installs) has no such branch.
pub const TEST_BUILD_LABELS_ENV: &str = "QSHD_TEST_BUILD_LABELS";

/// Monotonic build stamp (UNIX seconds of the HEAD commit; set by build.rs
/// via `cargo:rustc-env=QSHD_BUILD`). A version-ordering signal: built later
/// -> larger value. In a debug build, or one built with the
/// `test-build-labels` feature, [`TEST_BUILD_LABELS_ENV`] may name another
/// label for this very binary's checksum.
pub fn build_label() -> u64 {
    #[cfg(any(debug_assertions, feature = "test-build-labels"))]
    if let Some(label) = test_label_override() {
        return label;
    }
    env!("QSHD_BUILD").parse().unwrap_or(0)
}

#[cfg(any(debug_assertions, feature = "test-build-labels"))]
fn test_label_override() -> Option<u64> {
    let spec = std::env::var(TEST_BUILD_LABELS_ENV).ok()?;
    let own = self_checksum().ok()?;
    parse_label_overrides(&spec)
        .into_iter()
        .find(|(sum, _)| *sum == own)
        .map(|(_, label)| label)
}

/// `sum=label` entries, comma-separated; a malformed entry is skipped.
#[cfg_attr(
    not(any(debug_assertions, feature = "test-build-labels")),
    allow(dead_code)
)]
fn parse_label_overrides(spec: &str) -> Vec<(String, u64)> {
    spec.split(',')
        .filter_map(|entry| {
            let (sum, label) = entry.trim().split_once('=')?;
            if sum.is_empty() {
                return None;
            }
            Some((sum.to_string(), label.parse().ok()?))
        })
        .collect()
}

/// The version of the handover description this binary writes when it
/// replaces itself (`crate::handover::Handover`).
pub const HANDOVER_VERSION: u32 = 1;

/// The handover versions this binary can take a running daemon's state from.
pub const ACCEPTED_HANDOVER_VERSIONS: &[u32] = &[HANDOVER_VERSION];

/// The control-protocol versions this binary speaks.
pub const ACCEPTED_PROTOCOLS: &[u8] = &[transport::channel::PROTOCOL_VERSION];

/// What `qshd self-check` prints: enough for a running daemon to tell that a
/// staged binary starts at all on this machine, is the build it was
/// offered, still speaks the protocol its clients speak, and can take the
/// handover it is about to be given (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfCheck {
    pub build: u64,
    pub arch: String,
    /// The protocol version the binary prefers.
    pub protocol: u8,
    /// Every protocol version it speaks. Absent from a binary that predates
    /// the field: read as none.
    #[serde(default)]
    pub protocols: Vec<u8>,
    /// Every handover version it can take. Absent: none.
    #[serde(default)]
    pub handover_versions: Vec<u32>,
    /// The transport features this build implements (spec §5.5), by name.
    /// Informational: nothing checks it before a handover. Absent from a
    /// binary that predates negotiation: read as none. A daemon that
    /// predates the field skips it -- `SelfCheck` never denied unknown
    /// fields.
    #[serde(default)]
    pub transport_features: Vec<String>,
}

impl SelfCheck {
    /// This binary's own answer.
    pub fn current() -> SelfCheck {
        SelfCheck {
            build: build_label(),
            arch: std::env::consts::ARCH.to_string(),
            protocol: transport::channel::PROTOCOL_VERSION,
            protocols: ACCEPTED_PROTOCOLS.to_vec(),
            handover_versions: ACCEPTED_HANDOVER_VERSIONS.to_vec(),
            transport_features: transport::Features::SUPPORTED
                .names()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }

    /// One JSON line with a trailing `\n`.
    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).expect("a SelfCheck always serializes");
        line.push('\n');
        line
    }

    pub fn from_line(line: &str) -> Result<SelfCheck> {
        serde_json::from_str(line.trim()).context("parsing a self-check line")
    }
}

/// Where this process's binary lives on disk -- the path an update renames
/// the new binary onto. Unlike [`self_exe_path`] this is a real path, read
/// once at start-up, before anything could have renamed over it.
pub fn own_binary_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link("/proc/self/exe").context("reading /proc/self/exe")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().context("locating our own executable")
    }
}

/// The path [`self_checksum`] hashes. Split into its own function -- and
/// split BY PLATFORM inside that function -- because the two branches
/// below are not interchangeable and not a style choice; collapsing them
/// back into one `std::env::current_exe()` call (as a previous pass here
/// briefly did, chasing macOS support) reintroduces a real regression on
/// Linux, which is the one platform this daemon has to work correctly on
/// every day. Read this whole comment before "simplifying" it.
///
/// The two are usually interchangeable, and diverge only in one specific
/// situation this project actually hits: an in-place self-update, where a
/// freshly uploaded `qshd` binary is renamed OVER the path of an
/// already-running OLD daemon (see the upload in bootstrap) before that
/// old daemon is told `STOP`. A `STATUS` request landing in that short
/// window needs its OWN checksum -- the old daemon's -- and:
///
/// - [`std::env::current_exe`], on Linux, is *implemented* by reading the
///   TEXT of the `/proc/self/exe` symlink (a `readlink` call) and handing
///   back that string as a path. Once the rename above has happened, the
///   kernel renders that text as the deleted-inode form of the OLD daemon's
///   original path (`".../qshd (deleted)"`) -- a string that names no real
///   file on disk, so opening it fails. The `STATUS` handler would then
///   answer with an error, and the daemon "disappears" for version
///   reconciliation exactly when a client is trying to reconcile against
///   it.
/// - Opening `/proc/self/exe` DIRECTLY as a file -- not asking what it
///   resolves to as text, just `open()`-ing the magic link itself -- is a
///   different, kernel-level operation: it always dereferences to the
///   CALLING PROCESS'S live inode, independent of what happened to that
///   inode's name. It keeps working straight through the rename, because
///   it was never looking the file up by name in the first place.
///
/// So on Linux the correct read is the magic link, opened directly, NOT
/// `current_exe()`'s path. `run_transport_ensure` already stops the old
/// daemon before binding anything new, which keeps this window small; it
/// does not close it, so the distinction above still matters.
///
/// Linux is the only platform with `/proc`, so it is also the only one
/// where this trick is available. Everywhere else (macOS, today) there is
/// no equivalent, and `current_exe()` is the best available answer to
/// "which file is this process running from" -- without SOME answer,
/// `self_checksum` cannot run there AT ALL, breaking `STATUS` and version
/// reconciliation outright (see `self_checksum`'s doc comment for why that
/// matters for the "app installs the daemon over SSH" path on macOS). That
/// total failure is why non-Linux gets `current_exe()` rather than being
/// left unimplemented, even though it carries the narrower self-update
/// race described above.
fn self_exe_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().context("locating our own executable")
    }
}

/// Plain hex sha256 of our own executable -- the "same byte-for-byte
/// executable" signal used during version reconciliation. The format
/// matches the executable checksum used in bootstrap (no `sha256:` prefix).
///
/// The path hashed comes from [`self_exe_path`] -- see its doc comment for
/// why the choice of path is platform-specific and load-bearing, not
/// cosmetic.
///
/// CACHED for the life of the process: once resolving and hashing the
/// executable has succeeded once, the result stays valid for the rest of
/// the process's life -- a running process's own bytes do not rewrite
/// themselves out from under it -- so the checksum is a constant per
/// process and only needs computing once. This matters because the `STATUS`
/// control-socket handler (`transport_daemon::transport_status_response`)
/// calls this on EVERY request: hashing tens of megabytes with an unoptimized
/// debug-build `sha2` took over a second even idle, and several seconds
/// under CPU load, which could blow past the control client's read
/// timeout and make a live, merely-busy daemon look absent (see the
/// `client_request` changes in `control.rs`). A cached read is a `String`
/// clone -- microseconds.
///
/// A failed FIRST read must not poison every later call (transient I/O
/// errors should stay retriable), so only a SUCCESSFUL result is stored in
/// the `OnceLock`; a failure just returns `Err` without touching it.
static SELF_CHECKSUM: OnceLock<String> = OnceLock::new();

/// Test-only: counts how many times [`self_checksum`] actually found the
/// cache empty and recomputed, as opposed to returning the cached clone.
/// Exists so a test can assert "did not recompute" directly instead of
/// inferring it from wall-clock timing, which is noisy under load even
/// when the cache was never touched -- see
/// `self_checksum_second_call_does_not_recompute` below. Stripped out of
/// every non-test build; does not change `self_checksum`'s behavior.
#[cfg(test)]
static SELF_CHECKSUM_RECOMPUTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn self_checksum() -> Result<String> {
    if let Some(sum) = SELF_CHECKSUM.get() {
        return Ok(sum.clone());
    }
    #[cfg(test)]
    SELF_CHECKSUM_RECOMPUTES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let exe = self_exe_path()?;
    let computed = hash_file_streaming(&exe)?;
    Ok(SELF_CHECKSUM.get_or_init(|| computed).clone())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::hash_file_streaming;

    #[test]
    fn build_label_is_nonzero() {
        assert!(
            super::build_label() > 0,
            "the build stamp must be set by build.rs"
        );
    }

    #[test]
    fn self_checksum_is_64_hex() {
        let sum = super::self_checksum().expect("checksum of our own executable");
        assert_eq!(sum.len(), 64, "sha256 in hex is 64 characters");
        assert!(sum
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// Weakest possible property: two calls agree. On its own this would
    /// pass even without caching (hashing the same live executable twice
    /// is deterministic) -- it exists as a floor, not as the RED test for
    /// caching; see `self_checksum_second_call_does_not_recompute`
    /// for the test that actually distinguishes "cached" from "recomputed".
    #[test]
    fn self_checksum_agrees_across_calls() {
        let a = super::self_checksum().expect("first checksum");
        let b = super::self_checksum().expect("second checksum");
        assert_eq!(a, b, "the executable does not change identity mid-process");
    }

    /// This is the test that actually fails without a cache: an uncached
    /// `self_checksum` would recompute on every call, including the
    /// second one here. The property under test is "a call once the
    /// checksum is cached does not recompute it" -- checked directly via
    /// [`super::SELF_CHECKSUM_RECOMPUTES`] rather than inferred from
    /// wall-clock timing.
    ///
    /// This test used to compare `Instant::now()` deltas (asserting the
    /// second call was over 10x faster than the first) and was flaky: it
    /// depends on which test in this process warms `SELF_CHECKSUM` first.
    /// When a sibling test (e.g. `self_checksum_is_64_hex`, which also
    /// calls `self_checksum`) ran first and warmed the cache, THIS test's
    /// own "first" call became a cache hit too, so both calls were
    /// nanosecond-scale and the 10x comparison degenerated into a coin
    /// flip on scheduling noise -- it failed reliably whenever run after
    /// a sibling, and reliably passed run alone.
    ///
    /// The counter sidesteps that: by the time this test's own first call
    /// returns, `OnceLock` guarantees the cache is populated (whether by
    /// this call or by a sibling that raced it and won) -- so the second
    /// call is *always* a cache hit, and the recompute count between the
    /// two `load`s below must be zero, regardless of what ran earlier in
    /// this process or how loaded the machine is.
    #[test]
    fn self_checksum_second_call_does_not_recompute() {
        use std::sync::atomic::Ordering;

        super::self_checksum().expect("first checksum");
        let before = super::SELF_CHECKSUM_RECOMPUTES.load(Ordering::SeqCst);

        super::self_checksum().expect("second checksum");
        let after = super::SELF_CHECKSUM_RECOMPUTES.load(Ordering::SeqCst);

        assert_eq!(
            after, before,
            "a call once the checksum is cached must not recompute it \
             (recompute count went from {before} to {after})"
        );
    }

    /// `self_checksum` used to `fs::read` the whole file into a `Vec<u8>`
    /// and hash that buffer in one call; it now streams the file through
    /// the hasher in [`super::HASH_CHUNK_SIZE`]-sized chunks instead
    /// (`hash_file_streaming`). The resulting hex digest MUST be
    /// byte-identical either way -- it is
    /// compared against a checksum computed elsewhere during version
    /// reconciliation, so a mismatch would make every daemon look like a
    /// different build. Asserting the daemon's own executable checksum
    /// against a literal would not be portable (it depends on the exact
    /// build), so this compares the streaming path against an
    /// independently-computed whole-buffer digest of a FIXTURE file
    /// instead, at lengths straddling the chunk boundary on both sides (0,
    /// 1, boundary-1, boundary, boundary+1, and a few chunks past it) --
    /// exactly where an off-by-one in the read loop would show up.
    #[test]
    fn streaming_hash_matches_whole_buffer_hash_across_chunk_boundaries() {
        let chunk = super::HASH_CHUNK_SIZE;
        for len in [0usize, 1, chunk - 1, chunk, chunk + 1, chunk * 3 + 17] {
            let dir = tempfile::tempdir().expect("temp dir for a hashing fixture");
            let path = dir.path().join("fixture.bin");
            // Non-repeating-enough content (not all-zero, not all-same-byte)
            // so a chunk-copying bug (e.g. reusing a stale buffer tail)
            // would not accidentally still produce a matching digest.
            let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            std::fs::write(&path, &content).expect("write hashing fixture");

            let whole_buffer_digest = hex::encode(Sha256::digest(&content));
            let streamed_digest =
                hash_file_streaming(&path).expect("streamed digest of the fixture");
            assert_eq!(
                streamed_digest, whole_buffer_digest,
                "streaming digest must match a whole-buffer digest at length {len}"
            );
        }
    }

    #[test]
    fn label_overrides_are_read_entry_by_entry() {
        assert_eq!(
            super::parse_label_overrides("aa=1, bb=22 ,broken,cc=x,=3"),
            vec![("aa".to_string(), 1), ("bb".to_string(), 22)]
        );
        assert!(super::parse_label_overrides("").is_empty());
    }

    #[test]
    fn a_self_check_line_round_trips() {
        let check = super::SelfCheck {
            build: 42,
            arch: "x86_64".to_string(),
            protocol: 1,
            protocols: vec![1],
            handover_versions: vec![1],
            transport_features: vec!["header-aad".to_string()],
        };
        let line = check.to_line();
        assert!(line.ends_with('\n'));
        assert_eq!(super::SelfCheck::from_line(&line).unwrap(), check);
    }

    /// A binary that predates the lists says nothing about what it accepts:
    /// read as accepting nothing, so no daemon hands itself over to it.
    #[test]
    fn a_self_check_line_without_the_lists_accepts_nothing() {
        let check =
            super::SelfCheck::from_line(r#"{"build":1,"arch":"x86_64","protocol":1}"#).unwrap();
        assert!(check.protocols.is_empty());
        assert!(check.handover_versions.is_empty());
        assert!(check.transport_features.is_empty());
    }

    #[test]
    fn this_binary_knows_where_it_lives() {
        let path = super::own_binary_path().expect("own path");
        assert!(path.is_absolute(), "{}", path.display());
        assert!(path.exists(), "{}", path.display());
    }
}
