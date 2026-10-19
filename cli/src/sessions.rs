//! Which session for a login and endpoint this run should claim.
//!
//! The transport identifies a session by a 16-byte token the client chooses.
//! A token kept only in memory means every launch is a new shell: the old
//! session stays on the server (routable for a day) with no way back into it.
//! Keeping the token on disk is what turns a reconnect into a return.
//!
//! One token is not enough, though. Two terminals using the same login and
//! endpoint must not both claim the same session -- a warm reattach repoints
//! the server's session at the newer connection, so the second terminal would
//! silently steal the first one's shell. Each login/endpoint has SLOTS: slot 0,
//! slot 1, and so on, each with its own token. A run takes the lowest slot no
//! live process is holding.
//!
//! "Holding" is an exclusive `flock` on the slot's file. The acquiring
//! process explicitly unlocks it when its claim is dropped; a forked copy
//! only closes its descriptor. The kernel also releases the lock when the
//! last copy of its descriptor closes. There is no persistent pid file or
//! stale lock to clean up. A free slot with an existing token is the session
//! someone left behind, waiting to be returned to.

use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// How many slots one login/endpoint may have. Past this the run gives up on
/// resuming and takes a fresh token that is never written down. An unbounded
/// scan would turn a stuck lock into a hang.
const MAX_SLOTS: usize = 16;

/// The session token this run should use, and the lock that says it is ours.
pub struct Claim {
    pub token: [u8; 16],
    /// Owning-process drop releases the slot even while a concurrent child
    /// retains an inherited descriptor before exec. None for a throwaway token.
    _lock: Option<SlotLock>,
}

struct SlotLock {
    file: File,
    owner_pid: libc::pid_t,
}

impl SlotLock {
    // Construct immediately after successful flock, before fallible token I/O.
    fn new(file: File) -> Self {
        // SAFETY: getpid has no preconditions and is async-signal-safe.
        let owner_pid = unsafe { libc::getpid() };
        Self { file, owner_pid }
    }
}

impl Drop for SlotLock {
    fn drop(&mut self) {
        // SAFETY: getpid has no preconditions, including in a forked child.
        if unsafe { libc::getpid() } != self.owner_pid {
            return; // Field destruction closes only this copy's descriptor.
        }
        loop {
            // SAFETY: our File still owns the valid descriptor until this
            // destructor returns. Unlock the shared open-file description now.
            let result = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
            if result == 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break; // Other errors retain the existing best-effort close.
            }
        }
    }
}

impl Claim {
    /// Replace only this run's token, retaining its exclusive slot lock.
    pub fn replace_token(&mut self) -> std::io::Result<[u8; 16]> {
        let token = fresh_token();
        if let Some(slot) = &mut self._lock {
            let file = &mut slot.file;
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(format!("{}\n", hex(&token)).as_bytes())?;
            file.flush()?;
        }
        self.token = token;
        Ok(token)
    }
}

/// Claim a session slot for `login` at `host`:`port` under `dir`.
///
/// Legacy host-only records have no login attribution and are never claimed.
///
/// Never fails in a way the caller has to handle: a store that cannot be
/// created or read gives a fresh random token, which is exactly the old
/// behavior -- a new session every launch. Resuming is a convenience, and
/// losing it must not stop someone connecting.
pub fn claim(dir: &Path, login: &str, host: &str, port: u16) -> Claim {
    if std::fs::create_dir_all(dir).is_err() {
        return Claim {
            token: fresh_token(),
            _lock: None,
        };
    }
    // The directory holds session tokens: nobody else's business.
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));

    for slot in 0..MAX_SLOTS {
        let path = dir.join(slot_name(login, host, port, slot));
        let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
        else {
            continue;
        };
        if !lock_exclusive(&file) {
            // Another live `qsh` holds this slot: its session is not ours to
            // take.
            continue;
        }
        let mut slot = SlotLock::new(file);
        let file = &mut slot.file;
        let mut text = String::new();
        if file.read_to_string(&mut text).is_ok() {
            if let Some(token) = parse_token(text.trim()) {
                return Claim {
                    token,
                    _lock: Some(slot),
                };
            }
        }
        // Empty (a slot just created) or unreadable (a truncated write, a
        // hand-edited file): mint one and write it down. A failed write is
        // not fatal -- this run still gets a usable token, it just will not
        // be resumable.
        let token = fresh_token();
        let _ = file.set_len(0);
        // Truncating does not move the cursor, which the read above left at
        // the end of whatever was there: without this the new token would be
        // written AFTER the hole, and read back as junk next time.
        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.write_all(format!("{}\n", hex(&token)).as_bytes());
        let _ = file.flush();
        return Claim {
            token,
            _lock: Some(slot),
        };
    }

    Claim {
        token: fresh_token(),
        _lock: None,
    }
}

/// Default store location: `~/.config/qsh/sessions`, beside `known_hosts`.
pub fn default_dir() -> PathBuf {
    crate::paths::config_dir().join("sessions")
}

/// A versioned, bounded filename for the exact login/host/port tuple.
/// Length framing keeps delimiters and path characters unambiguous without
/// normalizing host aliases or allowing user input to escape the directory.
fn slot_name(login: &str, host: &str, port: u16, slot: usize) -> String {
    let mut hash = Sha256::new();
    hash.update(b"qsh/session-slot/v2\0");
    for text in [login, host] {
        hash.update((text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    hash.update(port.to_be_bytes());
    format!("v2-{:x}-{slot}", hash.finalize())
}

fn fresh_token() -> [u8; 16] {
    let mut token = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut token);
    token
}

fn hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_token(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut token = [0u8; 16];
    for (i, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(token)
}

/// A non-blocking exclusive `flock`. False means someone else holds it --
/// that slot's session belongs to a running process.
fn lock_exclusive(file: &File) -> bool {
    // SAFETY: `flock` takes a file descriptor and a constant; the descriptor
    // is owned by `file`, which outlives this call.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("sessions_inheritance_tests.rs");

    #[test]
    fn each_login_resumes_its_own_token_on_the_same_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let alice = claim(dir.path(), "alice", "example.org", 60000).token;
        let bob = claim(dir.path(), "bob", "example.org", 60000).token;
        assert_ne!(
            alice, bob,
            "a different login must not inherit a detached session"
        );
        assert_eq!(
            claim(dir.path(), "alice", "example.org", 60000).token,
            alice
        );
        assert_eq!(claim(dir.path(), "bob", "example.org", 60000).token, bob);
    }

    #[test]
    fn logins_hold_independent_numbered_slots_across_processes() {
        let dir = tempfile::tempdir().unwrap();
        let alice = claim(dir.path(), "alice", "example.org", 60000);
        let bob = claim(dir.path(), "bob", "example.org", 60000);
        let alice_second = claim(dir.path(), "alice", "example.org", 60000);
        for (login, slot, token) in [
            ("alice", 0, alice.token),
            ("bob", 0, bob.token),
            ("alice", 1, alice_second.token),
        ] {
            let path = dir
                .path()
                .join(slot_name(login, "example.org", 60000, slot));
            assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), hex(&token));
            assert_lock_from_subprocess(&path, false);
        }
        drop(alice);
        assert_lock_from_subprocess(
            &dir.path().join(slot_name("alice", "example.org", 60000, 0)),
            true,
        );
        assert_lock_from_subprocess(
            &dir.path().join(slot_name("bob", "example.org", 60000, 0)),
            false,
        );
        drop((bob, alice_second));
    }

    #[test]
    fn replacement_preserves_each_logins_token_and_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut alice = claim(dir.path(), "alice", "example.org", 60000);
        let mut bob = claim(dir.path(), "bob", "example.org", 60000);
        let bob_original = bob.token;
        let alice_replacement = alice.replace_token().unwrap();
        let alice_path = dir.path().join(slot_name("alice", "example.org", 60000, 0));
        let bob_path = dir.path().join(slot_name("bob", "example.org", 60000, 0));
        assert_eq!(
            std::fs::read_to_string(&bob_path).unwrap().trim(),
            hex(&bob_original)
        );
        assert_lock_from_subprocess(&alice_path, false);
        assert_lock_from_subprocess(&bob_path, false);
        let bob_replacement = bob.replace_token().unwrap();
        assert_ne!(bob_replacement, bob_original);
        assert_eq!(
            std::fs::read_to_string(&alice_path).unwrap().trim(),
            hex(&alice_replacement)
        );
        assert_lock_from_subprocess(&alice_path, false);
        assert_lock_from_subprocess(&bob_path, false);
        drop((alice, bob));
        assert_eq!(
            claim(dir.path(), "alice", "example.org", 60000).token,
            alice_replacement
        );
        assert_eq!(
            claim(dir.path(), "bob", "example.org", 60000).token,
            bob_replacement
        );
    }

    fn assert_lock_from_subprocess(path: &Path, available: bool) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sessions::tests::lock_probe_subprocess",
                "--nocapture",
            ])
            .env("QSH_TEST_SLOT_LOCK_PATH", path)
            .env("QSH_TEST_SLOT_LOCK_AVAILABLE", available.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "lock probe failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn lock_probe_subprocess() {
        let Some(path) = std::env::var_os("QSH_TEST_SLOT_LOCK_PATH") else {
            return;
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let expected = std::env::var("QSH_TEST_SLOT_LOCK_AVAILABLE").unwrap() == "true";
        assert_eq!(lock_exclusive(&file), expected);
    }

    #[test]
    fn legacy_records_are_never_claimed_or_changed_even_when_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.org_60000_0");
        let contents = "0123456789abcdef0123456789abcdef\n";
        std::fs::write(&path, contents).unwrap();
        let legacy_token = parse_token(contents.trim()).unwrap();
        for locked in [false, true] {
            let legacy = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            if locked {
                assert!(lock_exclusive(&legacy));
            }
            let alice = claim(dir.path(), "alice", "example.org", 60000);
            let bob = claim(dir.path(), "bob", "example.org", 60000);
            assert_ne!(alice.token, legacy_token);
            assert_ne!(bob.token, legacy_token);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
            assert_lock_from_subprocess(&path, !locked);
            drop((alice, bob, legacy));
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
        assert_lock_from_subprocess(&path, true);
    }

    #[test]
    fn slot_names_have_a_stable_versioned_format() {
        // Independently calculated SHA-256 of the specified framed tuple.
        let expected = "v2-b7b360904ec6958a055c0b82ca6d8072a9d9086822a71c5366d1b8aeb494a109-0";
        assert_eq!(slot_name("alice", "example.org", 60000, 0), expected);
        assert_eq!(slot_name("alice", "example.org", 60000, 0), expected);
    }

    #[test]
    fn tuple_framing_preserves_exact_names_without_path_or_length_collisions() {
        let tuples = [
            ("alice", "example.org", 60000),
            ("bob", "example.org", 60000),
            ("alice", "EXAMPLE.org", 60000),
            ("alice", "example.org.", 60000),
            ("alice", "example.org", 60001),
            ("alice", "other.example", 60000),
            ("a/b", "::1", 60000),
            ("a_b", "::1", 60000),
            ("a/b", "__1", 60000),
            ("a/b", "0:0:0:0:0:0:0:1", 60000),
            ("a:b", "c", 60000),
            ("a", "b:c", 60000),
            ("ab", "c", 60000),
            ("a", "bc", 60000),
            ("../用户", "../../etc/passwd", 60000),
            (".._用户", ".._.._etc_passwd", 60000),
        ];
        let mut names = std::collections::HashSet::new();
        for (login, host, port) in tuples {
            let name = slot_name(login, host, port, 0);
            assert_eq!(Path::new(&name).components().count(), 1);
            assert_eq!(name.len(), 69);
            assert!(
                names.insert(name),
                "tuple collision for {login:?}, {host:?}, {port}"
            );
        }
        let long = "用户/".repeat(1000);
        let name = slot_name(&long, &long, 60000, 15);
        assert_eq!(name.len(), 70);
        let dir = tempfile::tempdir().unwrap();
        let first = claim(dir.path(), &long, &long, 60000).token;
        assert_eq!(claim(dir.path(), &long, &long, 60000).token, first);
    }

    #[test]
    fn exhausting_one_login_does_not_consume_anothers_slots() {
        let dir = tempfile::tempdir().unwrap();
        let claims: Vec<_> = (0..16)
            .map(|_| claim(dir.path(), "alice", "example.org", 60000))
            .collect();
        let overflow = claim(dir.path(), "alice", "example.org", 60000);
        assert!(overflow._lock.is_none());
        let bob = claim(dir.path(), "bob", "example.org", 60000);
        assert!(bob._lock.is_some());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 17);
        drop((claims, overflow, bob));
    }

    #[test]
    fn an_unavailable_store_still_returns_a_fresh_unlocked_token() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let first = claim(file.path(), "alice", "example.org", 60000);
        let second = claim(file.path(), "alice", "example.org", 60000);
        assert!(first._lock.is_none());
        assert!(second._lock.is_none());
        assert_ne!(first.token, second.token);
    }

    #[test]
    fn replacing_a_token_keeps_the_claim_and_persists_only_its_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = claim(dir.path(), "alice", "example.org", 60000);
        let original = first.token;
        let second = claim(dir.path(), "alice", "example.org", 60000);
        let second_token = second.token;
        let replacement = first.replace_token().unwrap();
        assert_ne!(replacement, original);
        assert_ne!(replacement, second.token);
        drop(first);
        assert_eq!(
            claim(dir.path(), "alice", "example.org", 60000).token,
            replacement
        );
        drop(second);
        let held = claim(dir.path(), "alice", "example.org", 60000);
        assert_eq!(
            claim(dir.path(), "alice", "example.org", 60000).token,
            second_token
        );
        drop(held);
    }

    /// The whole point: the token a run is given is the one the previous run
    /// left behind, so the server hands back the same session.
    #[test]
    fn the_same_host_gets_the_same_token_next_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = claim(dir.path(), "alice", "example.org", 60000).token;
        // The first run ends: its lock goes with it.
        let second = claim(dir.path(), "alice", "example.org", 60000).token;
        assert_eq!(
            first, second,
            "a slot nobody holds is the session to return to"
        );
    }

    /// A second terminal to the same host must get its own session. Sharing
    /// the token would make the server repoint that session at the newer
    /// connection -- the first terminal's shell, silently taken away.
    #[test]
    fn a_second_run_while_the_first_holds_its_slot_gets_another_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = claim(dir.path(), "alice", "example.org", 60000);
        let second = claim(dir.path(), "alice", "example.org", 60000);
        assert_ne!(
            first.token, second.token,
            "a held slot is someone's live session, not a free one"
        );
        // And the second slot is itself resumable once released.
        let second_token = second.token;
        drop(second);
        let again = claim(dir.path(), "alice", "example.org", 60000);
        assert_ne!(again.token, first.token, "the first slot is still held");
        assert_eq!(
            again.token, second_token,
            "the freed slot is returned to, not replaced"
        );
    }

    /// Different hosts, and different ports on one host, are different
    /// sessions -- the daemon on each keeps its own.
    #[test]
    fn hosts_and_ports_do_not_share_a_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = claim(dir.path(), "alice", "example.org", 60000).token;
        let b = claim(dir.path(), "alice", "example.org", 60022).token;
        let c = claim(dir.path(), "alice", "other.example", 60000).token;
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// A token file someone truncated, edited or filled with junk must not
    /// take the run down with it: a fresh token is written over it.
    #[test]
    fn a_damaged_token_file_is_replaced_rather_than_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(slot_name("alice", "example.org", 60000, 0));
        std::fs::write(&path, "not a token at all\n").expect("write");
        let claimed = claim(dir.path(), "alice", "example.org", 60000);
        assert_ne!(claimed.token, [0u8; 16]);
        drop(claimed);
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text.trim().len(), 32, "a written token is 32 hex digits");
    }

    /// The store holds what amounts to a capability for a live shell: it is
    /// nobody else's business on a shared machine.
    #[test]
    fn the_store_keeps_its_files_to_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("sessions");
        let claimed = claim(&store, "alice", "example.org", 60000);
        drop(claimed);
        let dir_mode = std::fs::metadata(&store).expect("dir").permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(store.join(slot_name("alice", "example.org", 60000, 0)))
            .expect("file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the store directory is private");
        assert_eq!(file_mode, 0o600, "so is a token file");
    }
}
