//! Which session on a host this run should claim.
//!
//! The transport identifies a session by a 16-byte token the client chooses.
//! A token kept only in memory means every launch is a new shell: the old
//! session stays on the server (routable for a day) with no way back into it.
//! Keeping the token on disk is what turns a reconnect into a return.
//!
//! One token is not enough, though. Two terminals open to the same host must
//! not both claim the same session -- a warm reattach repoints the server's
//! session at the newer connection, so the second terminal would silently
//! steal the first one's shell. So a host has SLOTS: slot 0, slot 1, and so
//! on, each with its own token, and a run takes the lowest slot no live
//! process is holding.
//!
//! "Holding" is an exclusive `flock` on the slot's file, which the kernel
//! releases when the process dies however it dies -- there is no stale lock
//! to clean up, and no pid file to go wrong. A slot whose lock is free but
//! whose token file exists is exactly the case this module exists for: the
//! session someone left behind, waiting to be returned to.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// How many slots one host may have. Past this the run gives up on resuming
/// and takes a fresh token that is never written down -- a terminal is not
/// something a person opens sixteen of to the same host, and an unbounded
/// scan would turn a stuck lock into a hang.
const MAX_SLOTS: usize = 16;

/// The session token this run should use, and the lock that says it is ours.
pub struct Claim {
    pub token: [u8; 16],
    /// Dropped when the run ends (or the process dies), which releases the
    /// lock and leaves the slot free for the next run to return to. `None`
    /// when every slot was taken and this run got a throwaway token.
    _lock: Option<File>,
}

impl Claim {
    /// Replace only this run's token, retaining its exclusive slot lock.
    pub fn replace_token(&mut self) -> std::io::Result<[u8; 16]> {
        let token = fresh_token();
        if let Some(file) = &mut self._lock {
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(format!("{}\n", hex(&token)).as_bytes())?;
            file.flush()?;
        }
        self.token = token;
        Ok(token)
    }
}

/// Claim a session slot for `host`:`port` under `dir`.
///
/// Never fails in a way the caller has to handle: a store that cannot be
/// created or read gives a fresh random token, which is exactly the old
/// behavior -- a new session every launch. Resuming is a convenience, and
/// losing it must not stop someone connecting.
pub fn claim(dir: &Path, host: &str, port: u16) -> Claim {
    if std::fs::create_dir_all(dir).is_err() {
        return Claim {
            token: fresh_token(),
            _lock: None,
        };
    }
    // The directory holds session tokens: nobody else's business.
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));

    for slot in 0..MAX_SLOTS {
        let path = dir.join(slot_name(host, port, slot));
        let Ok(mut file) = OpenOptions::new()
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
        let mut text = String::new();
        if file.read_to_string(&mut text).is_ok() {
            if let Some(token) = parse_token(text.trim()) {
                return Claim {
                    token,
                    _lock: Some(file),
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
            _lock: Some(file),
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

/// A slot's file name. The host goes in verbatim except for characters that
/// have meaning in a path -- a host is user input, and `../` in a file name
/// would write wherever it liked.
fn slot_name(host: &str, port: u16, slot: usize) -> String {
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}_{port}_{slot}")
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

    #[test]
    fn replacing_a_token_keeps_the_claim_and_persists_only_its_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = claim(dir.path(), "example.org", 60000);
        let original = first.token;
        let second = claim(dir.path(), "example.org", 60000);
        let second_token = second.token;
        let replacement = first.replace_token().unwrap();
        assert_ne!(replacement, original);
        assert_ne!(replacement, second.token);
        drop(first);
        assert_eq!(claim(dir.path(), "example.org", 60000).token, replacement);
        drop(second);
        let held = claim(dir.path(), "example.org", 60000);
        assert_eq!(claim(dir.path(), "example.org", 60000).token, second_token);
        drop(held);
    }

    /// The whole point: the token a run is given is the one the previous run
    /// left behind, so the server hands back the same session.
    #[test]
    fn the_same_host_gets_the_same_token_next_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = claim(dir.path(), "example.org", 60000).token;
        // The first run ends: its lock goes with it.
        let second = claim(dir.path(), "example.org", 60000).token;
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
        let first = claim(dir.path(), "example.org", 60000);
        let second = claim(dir.path(), "example.org", 60000);
        assert_ne!(
            first.token, second.token,
            "a held slot is someone's live session, not a free one"
        );
        // And the second slot is itself resumable once released.
        let second_token = second.token;
        drop(second);
        let again = claim(dir.path(), "example.org", 60000);
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
        let a = claim(dir.path(), "example.org", 60000).token;
        let b = claim(dir.path(), "example.org", 60022).token;
        let c = claim(dir.path(), "other.example", 60000).token;
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// A host name is user input and ends up in a file name. Anything that
    /// could climb out of the store directory is replaced rather than
    /// escaped, so there is nothing to get wrong twice.
    #[test]
    fn a_host_name_cannot_escape_the_store_directory() {
        let name = slot_name("../../etc/passwd", 60000, 0);
        assert!(
            !name.contains('/'),
            "a slot file name must stay a file name, got {name:?}"
        );
        assert_eq!(name, ".._.._etc_passwd_60000_0");
    }

    /// A token file someone truncated, edited or filled with junk must not
    /// take the run down with it: a fresh token is written over it.
    #[test]
    fn a_damaged_token_file_is_replaced_rather_than_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(slot_name("example.org", 60000, 0));
        std::fs::write(&path, "not a token at all\n").expect("write");
        let claimed = claim(dir.path(), "example.org", 60000);
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
        let claimed = claim(&store, "example.org", 60000);
        drop(claimed);
        let dir_mode = std::fs::metadata(&store).expect("dir").permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(store.join(slot_name("example.org", 60000, 0)))
            .expect("file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the store directory is private");
        assert_eq!(file_mode, 0o600, "so is a token file");
    }
}
