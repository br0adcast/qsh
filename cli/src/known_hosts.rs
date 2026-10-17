//! The console's SSH `known_hosts` (spec §7.2): `~/.ssh/known_hosts` and
//! `/etc/ssh/ssh_known_hosts`, read the way OpenSSH reads them -- plain,
//! hashed, wildcard and negated patterns, `[host]:port` for another port,
//! `@revoked` -- and appended to after a person said yes. The core never
//! reads these files (`crates/ssh` takes the known keys as a parameter).

use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};

pub struct KnownHosts {
    user: PathBuf,
    system: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct HostKeys {
    pub known: Vec<Vec<u8>>,
    pub revoked: Vec<Vec<u8>>,
}

#[derive(PartialEq, Eq)]
enum Marker {
    None,
    Revoked,
    CertAuthority,
}

struct Entry<'a> {
    marker: Marker,
    patterns: &'a str,
    key: Vec<u8>,
}

pub fn entry_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

impl KnownHosts {
    pub fn new(user: PathBuf, system: Option<PathBuf>) -> KnownHosts {
        KnownHosts { user, system }
    }

    /// The file new keys are appended to.
    pub fn user_file(&self) -> &std::path::Path {
        &self.user
    }

    pub fn standard() -> KnownHosts {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        KnownHosts::new(
            home.join(".ssh").join("known_hosts"),
            Some(PathBuf::from("/etc/ssh/ssh_known_hosts")),
        )
    }

    pub fn lookup(&self, host: &str, port: u16) -> HostKeys {
        let name = entry_name(host, port).to_ascii_lowercase();
        let mut out = HostKeys::default();
        for file in std::iter::once(&self.user).chain(self.system.as_ref()) {
            let Ok(bytes) = std::fs::read(file) else {
                continue;
            };
            for line_bytes in bytes.split(|&b| b == b'\n') {
                let Ok(line) = std::str::from_utf8(line_bytes) else {
                    continue;
                };
                let Some(entry) = parse_line(line) else {
                    continue;
                };
                if !matches(entry.patterns, &name) {
                    continue;
                }
                let list = match entry.marker {
                    Marker::None => &mut out.known,
                    Marker::Revoked => &mut out.revoked,
                    Marker::CertAuthority => continue,
                };
                if !list.contains(&entry.key) {
                    list.push(entry.key);
                }
            }
        }
        let revoked = &out.revoked;
        out.known.retain(|k| !revoked.contains(k));
        out
    }

    pub fn add(&self, host: &str, port: u16, key_type: &str, wire: &[u8]) -> std::io::Result<()> {
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == ',' || c == '#') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host must not be empty or contain whitespace, comma, or hash",
            ));
        }
        if key_type.is_empty()
            || key_type.contains(|c: char| c.is_whitespace() || c == ',' || c == '#')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "key_type must not be empty or contain whitespace, comma, or hash",
            ));
        }
        if let Some(dir) = self.user.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let needs_newline = std::fs::read(&self.user)
            .map(|b| b.last().is_some_and(|c| *c != b'\n'))
            .unwrap_or(false);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.user)?;
        let mut text = String::new();
        if needs_newline {
            text.push('\n');
        }
        text.push_str(&format!(
            "{} {key_type} {}\n",
            entry_name(host, port),
            B64.encode(wire)
        ));
        file.write_all(text.as_bytes())
    }
}

fn parse_line(line: &str) -> Option<Entry<'_>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    let (marker, patterns) = match first {
        "@revoked" => (Marker::Revoked, fields.next()?),
        "@cert-authority" => (Marker::CertAuthority, fields.next()?),
        other if other.starts_with('@') => return None,
        other => (Marker::None, other),
    };
    let _key_type = fields.next()?;
    let key = B64.decode(fields.next()?).ok()?;
    Some(Entry {
        marker,
        patterns,
        key,
    })
}

/// OpenSSH's rule: any negated pattern that matches rules the line out;
/// otherwise any plain pattern that matches rules it in.
fn matches(patterns: &str, name: &str) -> bool {
    let mut hit = false;
    for pattern in patterns.split(',') {
        if let Some(negated) = pattern.strip_prefix('!') {
            if pattern_matches(negated, name) {
                return false;
            }
        } else if pattern_matches(pattern, name) {
            hit = true;
        }
    }
    hit
}

fn pattern_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix("|1|") {
        Some(hashed) => hashed_matches(hashed, name),
        None => glob(pattern.to_ascii_lowercase().as_bytes(), name.as_bytes()),
    }
}

fn hashed_matches(hashed: &str, name: &str) -> bool {
    let Some((salt, hash)) = hashed.split_once('|') else {
        return false;
    };
    let (Ok(salt), Ok(hash)) = (B64.decode(salt), B64.decode(hash)) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(name.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// `*` any run, `?` one character. Uses iterative two-pointer algorithm with
/// backtracking to avoid exponential recursion: O(n·m) time, O(1) space.
fn glob(p: &[u8], s: &[u8]) -> bool {
    let mut p_idx = 0;
    let mut s_idx = 0;
    let mut star_p = None;
    let mut star_s = None;

    loop {
        match (p.get(p_idx), s.get(s_idx)) {
            (None, None) => return true,
            (Some(&b'*'), _) => {
                star_p = Some(p_idx + 1);
                star_s = Some(s_idx);
                p_idx += 1;
            }
            (Some(&b'?'), Some(_)) => {
                p_idx += 1;
                s_idx += 1;
            }
            (Some(&pc), Some(&sc)) if pc == sc => {
                p_idx += 1;
                s_idx += 1;
            }
            (_, Some(_)) => {
                if let (Some(sp), Some(ss)) = (star_p, star_s) {
                    p_idx = sp;
                    s_idx = ss + 1;
                    star_s = Some(ss + 1);
                } else {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use hmac::{Hmac, Mac};

    const K1: &[u8] =
        b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20one-one-one-one-one-one-one-one-";
    const K2: &[u8] =
        b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20two-two-two-two-two-two-two-two-";

    fn line(patterns: &str, key: &[u8]) -> String {
        format!("{patterns} ssh-ed25519 {}\n", B64.encode(key))
    }

    fn store(user: &str) -> (tempfile::TempDir, KnownHosts) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, user).unwrap();
        let kh = KnownHosts::new(path, None);
        (dir, kh)
    }

    fn hashed(name: &str, salt: &[u8]) -> String {
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(salt).unwrap();
        mac.update(name.as_bytes());
        format!(
            "|1|{}|{}",
            B64.encode(salt),
            B64.encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn a_plain_name_matches_port_22_only() {
        let (_d, kh) = store(&line("host.example", K1));
        assert_eq!(kh.lookup("host.example", 22).known, vec![K1.to_vec()]);
        assert!(kh.lookup("host.example", 2222).known.is_empty());
    }

    #[test]
    fn another_port_uses_the_bracket_form() {
        let (_d, kh) = store(&line("[host.example]:2222", K1));
        assert_eq!(kh.lookup("host.example", 2222).known, vec![K1.to_vec()]);
        assert!(kh.lookup("host.example", 22).known.is_empty());
    }

    #[test]
    fn hashed_entries_match() {
        let text = line(&hashed("[host.example]:2222", b"0123456789abcdefghij"), K1);
        let (_d, kh) = store(&text);
        assert_eq!(kh.lookup("host.example", 2222).known, vec![K1.to_vec()]);
        assert!(kh.lookup("other.example", 2222).known.is_empty());
    }

    #[test]
    fn wildcards_and_negation_work_like_openssh() {
        let text = line("*.example,!bad.example", K1);
        let (_d, kh) = store(&text);
        assert_eq!(kh.lookup("good.example", 22).known, vec![K1.to_vec()]);
        assert!(kh.lookup("bad.example", 22).known.is_empty());
        let (_d, kh) = store(&line("h?st", K1));
        assert_eq!(kh.lookup("host", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn names_compare_without_case() {
        let (_d, kh) = store(&line("Host.Example", K1));
        assert_eq!(kh.lookup("host.EXAMPLE", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn a_revoked_key_is_reported_as_revoked() {
        let text = line("h", K1)
            + &line("h", K2)
            + &format!("@revoked h ssh-ed25519 {}\n", B64.encode(K1));
        let (_d, kh) = store(&text);
        let keys = kh.lookup("h", 22);
        assert_eq!(keys.known, vec![K2.to_vec()]);
        assert_eq!(keys.revoked, vec![K1.to_vec()]);
    }

    #[test]
    fn cert_authority_lines_are_skipped() {
        let text = format!("@cert-authority *.example ssh-ed25519 {}\n", B64.encode(K1));
        let (_d, kh) = store(&text);
        assert_eq!(kh.lookup("a.example", 22), HostKeys::default());
    }

    #[test]
    fn a_broken_line_does_not_hide_the_rest() {
        let text =
            "garbage\nh ssh-ed25519 !!!notbase64\n# comment\n\n".to_string() + &line("h", K1);
        let (_d, kh) = store(&text);
        assert_eq!(kh.lookup("h", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn the_system_file_is_read_too() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("ssh_known_hosts");
        std::fs::write(&system, line("h", K2)).unwrap();
        let kh = KnownHosts::new(dir.path().join("missing"), Some(system));
        assert_eq!(kh.lookup("h", 22).known, vec![K2.to_vec()]);
    }

    #[test]
    fn a_new_key_is_appended_and_found() {
        let (d, kh) = store("h ssh-ed25519 AAAA"); // no trailing newline
        kh.add("new.example", 2222, "ssh-ed25519", K1).unwrap();
        assert_eq!(kh.lookup("new.example", 2222).known, vec![K1.to_vec()]);
        let text = std::fs::read_to_string(d.path().join("known_hosts")).unwrap();
        assert!(
            text.starts_with("h ssh-ed25519 AAAA\n[new.example]:2222 ssh-ed25519 "),
            "{text}"
        );
    }

    #[test]
    fn adding_creates_the_directory_and_a_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".ssh").join("known_hosts");
        KnownHosts::new(path.clone(), None)
            .add("h", 22, "ssh-ed25519", K1)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
    }

    #[test]
    fn glob_with_many_stars_does_not_hang() {
        // 40 stars followed by 'x' against 30 'a's: should return false quickly
        let mut pattern = b"*".repeat(40);
        pattern.extend_from_slice(b"x");
        let name = b"a".repeat(30);
        assert!(!glob(&pattern, &name));

        // 100_000 stars should match anything without crashing
        let many_stars = b"*".repeat(100_000);
        assert!(glob(&many_stars, b"anything"));
        assert!(glob(&many_stars, b""));
    }

    #[test]
    fn non_utf8_line_does_not_hide_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        // File with: invalid UTF-8 comment, valid line K1, @revoked line K2
        let mut content = b"# bad comment: ".to_vec();
        content.push(0xff); // invalid UTF-8
        content.extend_from_slice(b"\n");
        content.extend_from_slice(line("h", K1).as_bytes());
        content
            .extend_from_slice(format!("@revoked h ssh-ed25519 {}\n", B64.encode(K2)).as_bytes());
        std::fs::write(&path, content).unwrap();
        let kh = KnownHosts::new(path, None);
        let keys = kh.lookup("h", 22);
        assert_eq!(keys.known, vec![K1.to_vec()]);
        assert_eq!(keys.revoked, vec![K2.to_vec()]);
    }

    #[test]
    fn the_same_key_twice_appears_once() {
        let text = line("h", K1) + &line("h", K1);
        let (_d, kh) = store(&text);
        assert_eq!(kh.lookup("h", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn the_same_key_in_both_files_appears_once() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("ssh_known_hosts");
        std::fs::write(&system, line("h", K1)).unwrap();
        let user_path = dir.path().join("known_hosts");
        std::fs::write(&user_path, line("h", K1)).unwrap();
        let kh = KnownHosts::new(user_path, Some(system));
        assert_eq!(kh.lookup("h", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn revoked_in_system_file_removes_known_from_user_file() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("ssh_known_hosts");
        std::fs::write(
            &system,
            format!("@revoked h ssh-ed25519 {}\n", B64.encode(K1)),
        )
        .unwrap();
        let user_path = dir.path().join("known_hosts");
        std::fs::write(&user_path, line("h", K1)).unwrap();
        let kh = KnownHosts::new(user_path, Some(system));
        let keys = kh.lookup("h", 22);
        assert!(keys.known.is_empty());
        assert_eq!(keys.revoked, vec![K1.to_vec()]);
    }

    #[test]
    fn tab_and_trailing_comment_are_accepted() {
        // OpenSSH allows tabs as separators and anything after the base64 as comment
        let text = "h\tssh-ed25519\t".to_string() + &B64.encode(K1) + " this is a comment\n";
        let (_d, kh) = store(&text);
        assert_eq!(kh.lookup("h", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn crlf_line_endings_work() {
        let text = format!("h ssh-ed25519 {}\r\n", B64.encode(K1));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, &text).unwrap();
        let kh = KnownHosts::new(path, None);
        // The \r becomes part of the patterns after splitting on \n, but trim() removes it
        assert_eq!(kh.lookup("h", 22).known, vec![K1.to_vec()]);
    }

    #[test]
    fn unknown_marker_is_skipped() {
        let text = format!("@unknown h ssh-ed25519 {}\n", B64.encode(K1)) + &line("h", K2);
        let (_d, kh) = store(&text);
        // Only K2 from the second line is found
        assert_eq!(kh.lookup("h", 22).known, vec![K2.to_vec()]);
    }

    #[test]
    fn hashed_entry_found_with_uppercase_lookup() {
        let text = line(&hashed("[host.example]:2222", b"0123456789abcdefghij"), K1);
        let (_d, kh) = store(&text);
        // lookup lowercases the search name internally
        assert_eq!(kh.lookup("HOST.EXAMPLE", 2222).known, vec![K1.to_vec()]);
    }

    #[test]
    fn negated_hashed_pattern_excludes_host() {
        let salt = b"0123456789abcdefghij";
        let h1 = hashed("[host.example]:2222", salt);
        let h2 = hashed("[other.example]:2222", salt);
        let text = format!("{},!{} ssh-ed25519 {}\n", h2, h1, B64.encode(K1));
        let (_d, kh) = store(&text);
        assert!(kh.lookup("host.example", 2222).known.is_empty());
        assert_eq!(kh.lookup("other.example", 2222).known, vec![K1.to_vec()]);
    }

    #[test]
    fn add_rejects_empty_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let kh = KnownHosts::new(path, None);
        let err = kh.add("", 22, "ssh-ed25519", K1);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn add_rejects_host_with_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let kh = KnownHosts::new(path, None);
        let err = kh.add("host name", 22, "ssh-ed25519", K1);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn add_rejects_host_with_comma_or_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let kh = KnownHosts::new(path, None);
        let err_comma = kh.add("host,name", 22, "ssh-ed25519", K1);
        assert!(err_comma.is_err());
        let err_hash = kh.add("host#name", 22, "ssh-ed25519", K1);
        assert!(err_hash.is_err());
    }

    #[test]
    fn add_rejects_empty_key_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let kh = KnownHosts::new(path, None);
        let err = kh.add("host", 22, "", K1);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn add_rejects_key_type_with_whitespace_comma_or_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let kh = KnownHosts::new(path, None);
        let err_space = kh.add("host", 22, "ssh ed25519", K1);
        assert!(err_space.is_err());
        let err_comma = kh.add("host", 22, "ssh,ed25519", K1);
        assert!(err_comma.is_err());
        let err_hash = kh.add("host", 22, "ssh#ed25519", K1);
        assert!(err_hash.is_err());
    }
}
