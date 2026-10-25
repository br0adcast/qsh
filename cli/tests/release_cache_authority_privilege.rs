//! Real ownership qualification, executed only in the existing disposable-root tier.
#[allow(dead_code)]
#[path = "support/releases.rs"]
mod support;
use bringup::{ImageError, ImageSource, InstallTiming};
use qsh::releases::GitHubImages;
use rustix::fs::{chownat, AtFlags, CWD};
use rustix::process::{Gid, Uid};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use support::*;

const CHILD_UID: u32 = 61001;
const OTHER_UID: u32 = 61002;
const ROLE: &str = "QSH_TEST_RELEASE_CACHE_ROLE";
const ROOT: &str = "QSH_TEST_RELEASE_CACHE_ROOT";
const TEST: &str = "release_cache_root_readonly_and_foreign_owner_boundaries";

fn load(root: &Path) -> Result<bringup::DaemonImage, ImageError> {
    let offline = Fake::offline();
    let result = GitHubImages::with_transport(root.into(), offline.clone()).load(
        &request(),
        &InstallTiming::default(),
        &knock::Cancel::new(),
        &Silent,
    );
    assert_eq!(offline.calls(), 1, "always attempt current metadata");
    result
}
fn chown(path: &Path, owner: u32) {
    chownat(
        CWD,
        path,
        Some(Uid::from_raw(owner)),
        Some(Gid::from_raw(owner)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
}
fn modes(path: &Path) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            modes(&entry.path());
        }
        fs::set_permissions(
            entry.path(),
            fs::Permissions::from_mode(if entry.file_type().unwrap().is_dir() {
                0o755
            } else {
                0o644
            }),
        )
        .unwrap();
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
#[derive(Debug, PartialEq)]
struct Snapshot {
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: Option<Vec<u8>>,
}
fn snapshot(path: &Path) -> Snapshot {
    let m = fs::symlink_metadata(path).unwrap();
    Snapshot {
        inode: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        links: m.nlink(),
        bytes: if m.is_file() {
            Some(fs::read(path).unwrap())
        } else {
            None
        },
    }
}

// One fixture-specific owner. Result observation is bounded; cleanup retains the
// exact Child and its borrowed TempDir until terminal wait, including wait errors.
struct OwnedChild<'a> {
    child: Option<Child>,
    _root: &'a tempfile::TempDir,
}
impl OwnedChild<'_> {
    fn finish(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait()? {
                self.child.take();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned cache child result deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild<'_> {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                let _ = child.kill();
            }
            Err(error) => {
                eprintln!("owned cache child observation failed; retaining custody: {error}")
            }
        }
        let mut reported = false;
        loop {
            match child.wait() {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    if !reported {
                        eprintln!("owned cache child wait failed; retaining custody: {error}");
                        reported = true;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}
fn run_child(root: &tempfile::TempDir, cache: &Path, role: &str) {
    let output_path = root.path().join("child-output");
    let output = fs::File::create(&output_path).unwrap();
    let mut child = OwnedChild {
        child: Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .uid(CHILD_UID)
                .gid(CHILD_UID)
                .env(ROLE, role)
                .env(ROOT, cache)
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
        ),
        _root: root,
    };
    let status = child.finish(Instant::now() + Duration::from_secs(5));
    // Drop completes custody before any parent assertion or fixture deletion.
    drop(child);
    let status = status.expect("owned cache child reached a terminal status");
    let mut bytes = Vec::new();
    fs::File::open(output_path)
        .unwrap()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024, "owned child output is bounded");
    let text = String::from_utf8(bytes).unwrap();
    assert!(status.success(), "{role}: {text}");
    assert!(
        text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "{role}: {text}"
    );
    assert!(
        text.contains(&format!(
            "qualified real effective UID/GID 61001/61001: {role}"
        )),
        "{role}: {text}"
    );
    assert!(!text.contains("SKIPPED"));
}

#[test]
fn release_cache_root_readonly_and_foreign_owner_boundaries() {
    if let Ok(role) = std::env::var(ROLE) {
        assert_eq!(rustix::process::geteuid().as_raw(), CHILD_UID);
        assert_eq!(rustix::process::getegid().as_raw(), CHILD_UID);
        let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
        let result = load(&root);
        if matches!(
            role.as_str(),
            "readonly"
                | "optional-repair"
                | "optional-foreign-image"
                | "optional-alias-image"
                | "optional-special-image"
        ) {
            assert_eq!(
                &*result.expect("trusted archive remains usable").bytes,
                IMAGE
            );
        } else {
            assert!(
                matches!(result, Err(ImageError::Download(_))),
                "required unsafe authority is not offline evidence"
            );
        }
        println!("qualified real effective UID/GID 61001/61001: {role}");
        return;
    }
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "this exact target requires the disposable-root tier"
    );
    assert_eq!(
        std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref(),
        Ok("1"),
        "never run against a personal root environment"
    );
    for role in [
        "readonly",
        "optional-repair",
        "root-lock",
        "readable-lock",
        "foreign-current",
        "foreign-receipt",
        "foreign-archive",
        "optional-foreign-image",
        "optional-alias-image",
        "optional-special-image",
    ] {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o755))
            .tempdir()
            .unwrap();
        let cache = root.path().join("cache");
        let bytes = archive();
        GitHubImages::with_transport(cache.clone(), Fake::new(bytes.clone()))
            .load(
                &request(),
                &InstallTiming::default(),
                &knock::Cancel::new(),
                &Silent,
            )
            .unwrap();
        modes(&cache);
        let target = cache.join("releases/0.4.0/x86_64-unknown-linux-musl");
        let generation = target.join("objects").join(digest(&bytes));
        let lock = target.join(".lock");
        chown(&lock, CHILD_UID);
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        let current = target.join("current.json");
        let receipt = generation.join("receipt.json");
        let archived = generation.join("archive");
        let image = generation.join("image");
        let sentinel = root.path().join("sentinel");
        fs::write(&sentinel, b"unrelated image sentinel").unwrap();
        fs::hard_link(&archived, root.path().join("public-archive-hardlink")).unwrap();
        assert!(fs::metadata(&archived).unwrap().nlink() > 1);
        match role {
            "readonly" => {}
            "optional-repair" => fs::write(&image, b"damaged optional image").unwrap(),
            "root-lock" => chown(&lock, 0),
            "readable-lock" => {
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "foreign-current" => chown(&current, OTHER_UID),
            "foreign-receipt" => chown(&receipt, OTHER_UID),
            "foreign-archive" => chown(&archived, OTHER_UID),
            "optional-foreign-image" => chown(&image, OTHER_UID),
            "optional-alias-image" => {
                fs::remove_file(&image).unwrap();
                std::os::unix::fs::symlink(&sentinel, &image).unwrap();
            }
            "optional-special-image" => {
                fs::remove_file(&image).unwrap();
                nix::unistd::mkfifo(
                    &image,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let files = [&current, &receipt, &archived, &image, &lock, &sentinel];
        let before: Vec<_> = files.iter().map(|path| snapshot(path)).collect();
        run_child(&root, &cache, role);
        let after: Vec<_> = files.iter().map(|path| snapshot(path)).collect();
        assert_eq!(
            before, after,
            "child must not mutate root/foreign/optional data: {role}"
        );
    }
}
