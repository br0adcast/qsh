//! Real UID boundaries; executed only by the existing disposable-root CI tier.
#![cfg(target_os = "linux")]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use qsh::known_hosts::KnownHosts;
use rustix::fs::{chownat, AtFlags, CWD};
use rustix::process::{Gid, Uid};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const UID: u32 = 61001;
const OTHER: u32 = 61002;
const TEST: &str = "ssh_known_hosts_real_owner_read_and_append_boundaries";
const ROLE: &str = "QSH_TEST_SSH_HOST_AUTHORITY_ROLE";
const ROOT: &str = "QSH_TEST_SSH_HOST_AUTHORITY_ROOT";
// Synthetic public record payloads qualify filesystem authority, not SSH KEX.
// The ladder PTY controls separately authenticate an actual generated host key.
const K1: &[u8] = b"owned SSH public record one";
const K2: &[u8] = b"owned SSH public record two";
fn line(host: &str, key: &[u8]) -> String {
    format!("{host} ssh-ed25519 {}\n", B64.encode(key))
}
fn owner(path: &Path, uid: u32) {
    chownat(
        CWD,
        path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(uid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
}
fn file(path: &Path, bytes: &[u8], uid: u32, mode: u32) {
    fs::write(path, bytes).unwrap();
    owner(path, uid);
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    dev: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    bytes: Option<Vec<u8>>,
    alias: Option<PathBuf>,
}
fn snapshot(path: &Path) -> Snapshot {
    let m = fs::symlink_metadata(path).unwrap();
    Snapshot {
        dev: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        bytes: m.is_file().then(|| fs::read(path).unwrap()),
        alias: m
            .file_type()
            .is_symlink()
            .then(|| fs::read_link(path).unwrap()),
    }
}
struct OwnedChild<'a> {
    child: Child,
    lost_wait: bool,
    _root: &'a tempfile::TempDir,
}
impl OwnedChild<'_> {
    fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        let result = self.child.try_wait();
        if let Err(error) = &result {
            self.lost_wait |= error.raw_os_error() == Some(libc::ECHILD);
        }
        result
    }
    fn result(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.poll()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned SSH authority child result deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild<'_> {
    fn drop(&mut self) {
        let mut killed = false;
        let mut reported = false;
        loop {
            match self.poll() {
                Ok(Some(_)) => return,
                Err(error) => {
                    if !reported {
                        eprintln!(
                            "owned SSH authority child wait failed; retaining custody: {error}"
                        );
                        reported = true;
                    }
                    if !self.lost_wait && !killed {
                        let _ = self.child.kill();
                        killed = true;
                    }
                }
                Ok(None) if !self.lost_wait && !killed => {
                    let _ = self.child.kill();
                    killed = true;
                }
                Ok(None) => {}
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
fn run(root: &tempfile::TempDir, role: &str) {
    let output_path = root.path().join("child-output");
    let output = fs::File::create(&output_path).unwrap();
    let mut child = OwnedChild {
        child: Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .uid(UID)
            .gid(UID)
            .env(ROLE, role)
            .env(ROOT, root.path())
            .env("HOME", root.path())
            .env("XDG_CACHE_HOME", root.path())
            .env("XDG_CONFIG_HOME", root.path())
            .env("HISTFILE", "/dev/null")
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
        lost_wait: false,
        _root: root,
    };
    let result = child.result();
    drop(child); // Retain exact ownership through every error before assertions.
    let mut bytes = Vec::new();
    fs::File::open(output_path)
        .unwrap()
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 32 * 1024, "owned child output is bounded");
    let text = String::from_utf8(bytes).unwrap();
    assert!(result.unwrap().success(), "{role}: {text}");
    assert!(
        text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "{role}: {text}"
    );
    assert!(
        text.contains(&format!("qualified effective UID/GID61001/61001: {role}")),
        "{role}: {text}"
    );
    assert!(!text.contains("SKIPPED"));
}
fn child(root: &Path, role: &str) {
    assert_eq!(rustix::process::geteuid().as_raw(), UID);
    assert_eq!(rustix::process::getegid().as_raw(), UID);
    let user = root.join("user");
    let stores = KnownHosts::new(user.clone(), Some(root.join("system")));
    match role {
        "root-read" => {
            let keys = stores.lookup("h", 22).unwrap();
            assert_eq!(keys.known, vec![K2.to_vec()]);
            assert_eq!(keys.revoked, vec![K1.to_vec()]);
        }
        "root-leaf" => {
            assert_eq!(stores.lookup("h", 22).unwrap().known, vec![K1.to_vec()]);
            assert_eq!(
                stores.add("new", 22, "ssh-ed25519", K2).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        "owned-data" => {
            assert_eq!(stores.lookup("h", 22).unwrap().known, vec![K1.to_vec()]);
            stores.add("new", 22, "ssh-ed25519", K2).unwrap();
            assert_eq!(stores.lookup("new", 22).unwrap().known, vec![K2.to_vec()]);
        }
        "alias-hardlink" => {
            KnownHosts::new(root.join("alias"), None)
                .add("alias", 22, "ssh-ed25519", K2)
                .unwrap();
            KnownHosts::new(root.join("hardlink"), None)
                .add("hard", 22, "ssh-ed25519", K2)
                .unwrap();
            assert_eq!(stores.lookup("alias", 22).unwrap().known, vec![K2.to_vec()]);
            assert_eq!(stores.lookup("hard", 22).unwrap().known, vec![K2.to_vec()]);
        }
        "root-create" => {
            for path in [
                root.join("missing"),
                root.join("missing-parent/known_hosts"),
            ] {
                assert_eq!(
                    KnownHosts::new(path, None)
                        .add("new", 22, "ssh-ed25519", K2)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
            }
        }
        "foreign-read" => {
            for store in [
                KnownHosts::new(root.join("foreign"), None),
                KnownHosts::new(user.clone(), Some(root.join("foreign"))),
            ] {
                let error = store.lookup("h", 22).unwrap_err();
                assert_eq!(error.path, root.join("foreign"));
                assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
            }
        }
        "writable" => {
            for path in [user, root.join("writable-parent/known_hosts")] {
                let store = KnownHosts::new(path.clone(), None);
                assert_eq!(
                    store.lookup("h", 22).unwrap_err().source.kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert_eq!(
                    store.add("new", 22, "ssh-ed25519", K2).unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
            }
        }
        "readonly-owned" => {
            assert_eq!(stores.lookup("h", 22).unwrap().known, vec![K1.to_vec()]);
            assert_eq!(
                stores
                    .add("new", 22, "ssh-ed25519", K2)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
        }
        _ => panic!("unknown owned role"),
    }
    println!("qualified effective UID/GID61001/61001: {role}");
}
#[test]
fn ssh_known_hosts_real_owner_read_and_append_boundaries() {
    if let Ok(role) = std::env::var(ROLE) {
        child(&PathBuf::from(std::env::var_os(ROOT).unwrap()), &role);
        return;
    }
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "requires the disposable-root tier"
    );
    assert_eq!(
        std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref(),
        Ok("1"),
        "never run against personal root state"
    );
    for role in [
        "root-read",
        "root-leaf",
        "owned-data",
        "alias-hardlink",
        "root-create",
        "foreign-read",
        "writable",
        "readonly-owned",
    ] {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o755))
            .tempdir()
            .unwrap();
        let user = root.path().join("user");
        let system = root.path().join("system");
        file(
            &user,
            line("h", K1).as_bytes(),
            if matches!(role, "root-read" | "root-leaf") {
                0
            } else {
                UID
            },
            if role == "readonly-owned" {
                0o444
            } else {
                0o644
            },
        );
        file(&system, b"# trusted system records\n", 0, 0o444);
        let mut paths = vec![root.path().to_path_buf(), user.clone(), system.clone()];
        match role {
            "root-read" => {
                file(&user, (line("h", K1) + &line("h", K2)).as_bytes(), 0, 0o444);
                file(
                    &system,
                    format!("@revoked {}", line("h", K1)).as_bytes(),
                    0,
                    0o444,
                );
                let hard = root.path().join("public-hardlink");
                fs::hard_link(&user, &hard).unwrap();
                paths.push(hard);
            }
            "alias-hardlink" => {
                let alias = root.path().join("alias");
                let hard = root.path().join("hardlink");
                symlink("user", &alias).unwrap();
                fs::hard_link(&user, &hard).unwrap();
                paths.extend([alias, hard]);
            }
            "foreign-read" => {
                let path = root.path().join("foreign");
                file(&path, line("h", K2).as_bytes(), OTHER, 0o644);
                paths.push(path);
            }
            "writable" => {
                fs::set_permissions(&user, fs::Permissions::from_mode(0o666)).unwrap();
                let parent = root.path().join("writable-parent");
                fs::create_dir(&parent).unwrap();
                owner(&parent, UID);
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
                let path = parent.join("known_hosts");
                file(&path, line("h", K1).as_bytes(), UID, 0o644);
                paths.extend([parent, path]);
            }
            _ => {}
        }
        let mut expected: Vec<_> = paths.iter().map(|p| snapshot(p)).collect();
        if matches!(role, "owned-data" | "alias-hardlink") {
            let bytes = if role == "owned-data" {
                line("h", K1) + &line("new", K2)
            } else {
                line("h", K1) + &line("alias", K2) + &line("hard", K2)
            };
            for s in &mut expected {
                if s.bytes.is_some() && s.uid == UID {
                    s.bytes = Some(bytes.as_bytes().to_vec());
                }
            }
        }
        run(&root, role);
        let actual: Vec<_> = paths.iter().map(|p| snapshot(p)).collect();
        assert_eq!(
            actual, expected,
            "unexpected metadata/data mutation: {role}"
        );
        assert!(!root.path().join("missing").exists());
        assert!(!root.path().join("missing-parent").exists());
    }
}
