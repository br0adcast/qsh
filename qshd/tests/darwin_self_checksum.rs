//! Cold production checksum/STATUS lookup in fresh processes. Linux exercises
//! the harness and its existing /proc behavior; Darwin is the regression gate.
#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const LIMIT: u64 = 512 * 1024 * 1024;
const CASE: &str = "QSHD_COLD_CHECKSUM_CASE";
// No sibling test may spawn while a copy is open for writing (ETXTBSY).
static SERIAL: Mutex<()> = Mutex::new(());
static BUDGET: OnceLock<Instant> = OnceLock::new();
type Identity = (u64, u64, u64, u32, i64, i64, i64, i64);

fn identity(meta: &fs::Metadata) -> Identity {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mode(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}
fn remaining(end: Instant) -> Duration {
    end.checked_duration_since(Instant::now())
        .filter(|n| !n.is_zero())
        .expect("fixture deadline")
}
fn open(path: &Path) -> File {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .expect("fixture input");
    let meta = file.metadata().unwrap();
    assert!(
        meta.is_file() && (1..=LIMIT).contains(&meta.len()),
        "fixture input bound"
    );
    assert_eq!(
        identity(&meta),
        identity(&fs::symlink_metadata(path).unwrap())
    );
    file
}
fn bound(file: &File, path: &Path, expected: Identity) {
    assert_eq!(identity(&file.metadata().unwrap()), expected);
    assert_eq!(identity(&fs::symlink_metadata(path).unwrap()), expected);
}
fn hash(file: &mut File, size: u64, end: Instant) -> String {
    remaining(end);
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = [0; 64 * 1024];
    let mut count = 0;
    let mut digest = Sha256::new();
    loop {
        remaining(end);
        let limit = (size - count + 1).min(buffer.len() as u64) as usize;
        let n = file.read(&mut buffer[..limit]).unwrap();
        remaining(end);
        if n == 0 {
            break;
        }
        count += n as u64;
        assert!(count <= size, "fixture source growth");
        digest.update(&buffer[..n]);
    }
    assert_eq!(count, size);
    hex::encode(digest.finalize())
}
fn copy(source: &mut File, size: u64, destination: &Path, end: Instant) {
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .unwrap();
    let mut buffer = [0; 64 * 1024];
    let mut count = 0;
    loop {
        remaining(end);
        let limit = (size - count + 1).min(buffer.len() as u64) as usize;
        let n = source.read(&mut buffer[..limit]).unwrap();
        remaining(end);
        if n == 0 {
            break;
        }
        count += n as u64;
        assert!(count <= size, "fixture source growth");
        output.write_all(&buffer[..n]).unwrap();
    }
    assert_eq!(count, size);
    output
        .set_permissions(fs::Permissions::from_mode(0o700))
        .unwrap();
    output.sync_all().unwrap();
    // The only writer is closed before any child is spawned.
}

struct Running(Child);
impl Running {
    fn collect(&mut self, end: Instant) -> (ExitStatus, Vec<u8>) {
        let mut pipe = self.0.stderr.take().unwrap();
        let fd = pipe.as_raw_fd();
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        assert!(
            flags >= 0
                && unsafe {
                    nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK)
                } >= 0
        );
        let mut bytes = Vec::new();
        let mut status = None;
        let mut eof = false;
        let mut buffer = [0; 1024];
        loop {
            remaining(end);
            if !eof {
                match pipe.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        assert!(bytes.len() + n <= 1024, "fixture output bound");
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => panic!("fixture pipe refused"),
                }
            }
            if status.is_none() {
                status = self.0.try_wait().unwrap();
            }
            remaining(end);
            if let Some(status) = status {
                if eof {
                    return (status, bytes);
                }
            }
            std::thread::sleep(remaining(end).min(Duration::from_millis(1)));
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.0.stderr.take();
        if self.0.try_wait().expect("fixture child status").is_none() {
            let _ = self.0.kill();
            self.0.wait().expect("fixture failure cleanup wait");
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Facts {
    bytes: u64,
    checks: [bool; 4],
    old_absent: bool,
    renamed: bool,
    same_inode: bool,
    schema: u8,
    sha256: String,
    unchanged: bool,
}
fn record(facts: &Facts) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(facts).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn cold_checksum_actor() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    std::panic::set_hook(Box::new(|_| eprintln!("CHECKSUM_ACTOR_FIXTURE_REFUSED")));
    assert!(matches!(case.as_str(), "baseline" | "renamed"));
    let end = Instant::now() + Duration::from_secs(10);
    let old = std::env::current_exe().unwrap();
    assert!(
        old.file_name() == Some(std::ffi::OsStr::new("checksum-actor")),
        "actor requires its private copied image"
    );
    let new = old.with_file_name("renamed-image");
    assert!(
        matches!(fs::symlink_metadata(&new), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    );
    let mut file = open(&old);
    let before = identity(&file.metadata().unwrap());
    let expected = hash(&mut file, before.2, end);
    bound(&file, &old, before);
    let renamed = case == "renamed";
    if renamed {
        fs::rename(&old, &new).unwrap();
    }
    let selected = if renamed { &new } else { &old };
    let after = identity(&file.metadata().unwrap());
    let same_inode = (before.0, before.1) == (after.0, after.1);
    let old_absent = match fs::symlink_metadata(&old) {
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => panic!("fixture pathname refused"),
    };
    assert!(same_inode && old_absent == renamed);
    assert_eq!(hash(&mut file, before.2, end), expected);
    bound(&file, selected, after);
    // These are the first production checksum/STATUS calls in this process.
    let sum = qshd::state::self_checksum();
    let status = qshd::transport_daemon::transport_status_response(&[], 0, None);
    let cached_sum = qshd::state::self_checksum();
    let cached_status = qshd::transport_daemon::transport_status_response(&[], 0, None);
    remaining(end);
    let facts = Facts {
        bytes: before.2,
        checks: [
            sum.is_ok_and(|v| v == expected),
            status.is_ok_and(|v| v.checksum == expected),
            cached_sum.is_ok_and(|v| v == expected),
            cached_status.is_ok_and(|v| v.checksum == expected),
        ],
        old_absent,
        renamed,
        same_inode,
        schema: 1,
        sha256: expected.clone(),
        unchanged: hash(&mut file, before.2, end) == expected,
    };
    bound(&file, selected, after);
    let bytes = record(&facts);
    assert!(bytes.len() <= 1024);
    std::io::stderr().write_all(&bytes).unwrap();
}

fn run(renamed: bool) {
    // An expected product regression must not prevent the other control from
    // running after its owned child and temporary files have settled.
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let end = *BUDGET.get_or_init(|| Instant::now() + Duration::from_secs(30));
    let directory = tempfile::tempdir().unwrap();
    let source_path = std::env::current_exe().unwrap();
    let mut source = open(&source_path);
    let source_identity = identity(&source.metadata().unwrap());
    let expected = hash(&mut source, source_identity.2, end);
    let image = directory.path().join("checksum-actor");
    copy(&mut source, source_identity.2, &image, end);
    bound(&source, &source_path, source_identity);
    let mut copied = open(&image);
    let copied_identity = identity(&copied.metadata().unwrap());
    assert_eq!(hash(&mut copied, source_identity.2, end), expected);
    bound(&copied, &image, copied_identity);
    let child_end = end.min(Instant::now() + Duration::from_secs(10));
    remaining(child_end);
    let mut child = Running(
        Command::new(&image)
            .args(["--exact", "cold_checksum_actor", "--nocapture"])
            .env(CASE, if renamed { "renamed" } else { "baseline" })
            .env("HOME", directory.path())
            .env("XDG_CONFIG_HOME", directory.path().join("config"))
            .env("XDG_CACHE_HOME", directory.path().join("cache"))
            .env("HISTFILE", "/dev/null")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (status, bytes) = child.collect(child_end);
    assert!(status.success(), "checksum actor fixture refused");
    let facts: Facts = serde_json::from_slice(&bytes).expect("checksum actor record refused");
    assert_eq!(record(&facts), bytes);
    assert!(
        facts.schema == 1
            && facts.renamed == renamed
            && facts.same_inode
            && facts.old_absent == renamed
            && facts.unchanged
    );
    assert_eq!(
        (facts.sha256.as_str(), facts.bytes),
        (expected.as_str(), source_identity.2)
    );
    bound(&source, &source_path, source_identity);
    remaining(end);
    eprintln!(
        "cold checksum facts: {}",
        std::str::from_utf8(&bytes).unwrap().trim_end()
    );
    assert!(
        facts.checks.into_iter().all(|ok| ok),
        "cold checksum and STATUS must survive a same-inode rename"
    );
}
#[test]
fn unchanged_image_keeps_cold_checksum() {
    run(false);
}
#[test]
fn renamed_image_keeps_cold_checksum() {
    run(true);
}
