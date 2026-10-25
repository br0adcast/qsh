//! Actual owner boundaries in one disposable-root CI container, never host sudo.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read, Seek};
use std::os::unix::fs::{chown, symlink, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use sshauth::known_hosts::{HostVerdict, KnownHosts};
use transport::auth::AuthError;

const NAME: &str = "qsh_pin_real_account_root_read_and_mutation_boundaries";
const ROLE: &str = "QSH_PIN_AUTHORITY_CHILD";
const UID: u32 = 61001;
const FOREIGN: u32 = 61002;
const KEY: [u8; 32] = [23; 32];

fn owned(path: &Path, uid: u32, mode: u32) {
    chown(path, Some(uid), Some(uid)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn record() -> String {
    format!(
        "fixture.invalid 22 {}\n",
        base64::engine::general_purpose::STANDARD.encode(KEY)
    )
}
fn sibling(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".{}.lock",
        path.file_name().unwrap().to_str().unwrap()
    ))
}
fn evidence(path: &Path) -> (u64, u64, u32, u32, Vec<u8>) {
    let m = fs::metadata(path).unwrap();
    (m.dev(), m.ino(), m.uid(), m.mode(), fs::read(path).unwrap())
}
fn metadata(path: &Path) -> (u64, u64, u32, u32) {
    let m = fs::symlink_metadata(path).unwrap();
    (m.dev(), m.ino(), m.uid(), m.mode())
}

// A result deadline is not cleanup. Only an exact terminal wait releases the
// child; the parent owns its TempDir until this guard has completed.
struct OwnedChild {
    child: Child,
    terminal: bool,
    lost_identity: bool,
}
impl OwnedChild {
    fn wait(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.terminal = true;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    self.lost_identity |= error.raw_os_error() == Some(libc::ECHILD);
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pin authority child did not finish",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        if !self.lost_identity {
            let _ = self.child.kill();
        }
        let mut reported = false;
        loop {
            match self.child.wait() {
                Ok(_) => {
                    self.terminal = true;
                    return;
                }
                Err(error) => {
                    if !reported {
                        eprintln!(
                            "pin fixture retains exact Child and TempDir after wait error: {error}"
                        );
                        reported = true;
                    }
                    // No further numeric-PID termination after ECHILD. It is
                    // still not terminal evidence or permission to free paths.
                    self.lost_identity |= error.raw_os_error() == Some(libc::ECHILD);
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

fn child() {
    assert_eq!(rustix::process::geteuid().as_raw(), UID);
    assert_eq!(rustix::process::getegid().as_raw(), UID);
    assert!(rustix::process::getgroups()
        .unwrap()
        .iter()
        .all(|g| g.as_raw() != 0));
    let parent: u32 = std::env::var("QSH_PIN_AUTHORITY_PARENT")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        rustix::process::getppid().unwrap().as_raw_nonzero().get() as u32,
        parent
    );
    let root = PathBuf::from(std::env::var_os("QSH_PIN_AUTHORITY_ROOT").unwrap());
    assert_eq!(root.parent(), Some(Path::new("/var/lib")));
    assert!(root
        .file_name()
        .unwrap()
        .as_encoded_bytes()
        .starts_with(b"qsh-pin-authority-"));
    let m = fs::metadata(&root).unwrap();
    assert_eq!((m.uid(), m.mode() & 0o7777), (0, 0o755));

    let readonly = root.join("readonly/pins");
    let before = evidence(&readonly);
    let lock_before = evidence(&sibling(&readonly));
    let hosts = KnownHosts::open(readonly.clone());
    assert_eq!(
        hosts.check("fixture.invalid", 22, &KEY).unwrap(),
        HostVerdict::Known
    );
    hosts.pin("fixture.invalid", 22, &KEY).unwrap();
    assert_eq!(
        hosts.pin_if_absent("fixture.invalid", 22, &KEY).unwrap(),
        HostVerdict::Known
    );
    assert_eq!(
        hosts
            .pin_if_absent("fixture.invalid", 22, &[24; 32])
            .unwrap(),
        HostVerdict::Changed { pinned: KEY }
    );
    assert!(matches!(
        hosts.pin("new.invalid", 22, &[24; 32]),
        Err(AuthError::Backend(_))
    ));
    assert!(matches!(
        hosts.pin("fixture.invalid", 22, &[24; 32]),
        Err(AuthError::Backend(_))
    ));
    assert_eq!(evidence(&readonly), before);
    assert_eq!(evidence(&sibling(&readonly)), lock_before);
    let missing_lock = root.join("readonly/no-lock");
    let hosts = KnownHosts::open(missing_lock.clone());
    assert_eq!(
        hosts.check("fixture.invalid", 22, &KEY).unwrap(),
        HostVerdict::Known
    );
    assert!(hosts.pin("fixture.invalid", 22, &KEY).is_err());
    assert!(!sibling(&missing_lock).exists());

    let external = root.join("external");
    let outside = evidence(&external);
    for name in ["public-hardlink", "public-alias"] {
        let path = root.join("account").join(name);
        let hosts = KnownHosts::open(path.clone());
        assert_eq!(
            hosts.check("fixture.invalid", 22, &KEY).unwrap(),
            HostVerdict::Known
        );
        hosts.pin("new.invalid", 22, &[24; 32]).unwrap();
        assert_eq!(
            hosts.check("new.invalid", 22, &[24; 32]).unwrap(),
            HostVerdict::Known
        );
        let m = fs::symlink_metadata(&path).unwrap();
        assert!(m.is_file());
        assert_eq!((m.uid(), m.mode() & 0o7777), (UID, 0o600));
        assert_eq!(evidence(&external), outside);
        assert!(sibling(&path).is_file());
    }
    assert!(
        !root.join(".external.lock").exists(),
        "alias target cannot choose the lock domain"
    );
    for name in [
        "account/foreign",
        "foreign-parent/pins",
        "account/foreign-alias",
        "account/writable",
    ] {
        let path = root.join(name);
        let before = evidence(&path);
        let hosts = KnownHosts::open(path.clone());
        assert!(
            matches!(
                hosts.check("fixture.invalid", 22, &KEY),
                Err(AuthError::Backend(_))
            ),
            "{name}"
        );
        assert!(
            matches!(
                hosts.pin("fixture.invalid", 22, &KEY),
                Err(AuthError::Backend(_))
            ),
            "{name}"
        );
        assert!(
            matches!(
                hosts.pin_if_absent("fixture.invalid", 22, &KEY),
                Err(AuthError::Backend(_))
            ),
            "{name}"
        );
        assert_eq!(evidence(&path), before, "{name}");
    }
    let path = root.join("account/unsafe-lock");
    let before = evidence(&path);
    // This child cannot read the root-owned0600 lock. Its root parent
    // checks the sentinel bytes after the exact terminal child wait.
    let lock = metadata(&sibling(&path));
    let hosts = KnownHosts::open(path.clone());
    assert_eq!(
        hosts.check("fixture.invalid", 22, &KEY).unwrap(),
        HostVerdict::Known
    );
    assert!(hosts.pin("fixture.invalid", 22, &KEY).is_err());
    assert!(hosts.pin_if_absent("fixture.invalid", 22, &KEY).is_err());
    assert_eq!(evidence(&path), before);
    assert_eq!(metadata(&sibling(&path)), lock);
    println!("validated actual root/account/foreign QSH pin read and publication boundaries");
}

#[test]
fn qsh_pin_real_account_root_read_and_mutation_boundaries() {
    if std::env::var_os(ROLE).is_some() {
        child();
        return;
    }
    if rustix::process::geteuid().as_raw() != 0
        || std::env::var("QSH_PIN_TEST_DISPOSABLE_HOST").as_deref() != Ok("1")
    {
        eprintln!("SKIPPED {NAME}: requires the disposable root CI container");
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("qsh-pin-authority-")
        .tempdir_in("/var/lib")
        .unwrap();
    owned(root.path(), 0, 0o755);
    for (name, uid) in [
        ("readonly", 0),
        ("account", UID),
        ("foreign-parent", FOREIGN),
    ] {
        let dir = root.path().join(name);
        fs::create_dir(&dir).unwrap();
        owned(&dir, uid, 0o755);
    }
    for (name, uid, mode) in [
        ("readonly/pins", 0, 0o644),
        ("readonly/no-lock", 0, 0o644),
        ("external", 0, 0o644),
        ("account/foreign", FOREIGN, 0o644),
        ("foreign-parent/pins", UID, 0o644),
        ("account/writable", UID, 0o664),
        ("account/unsafe-lock", UID, 0o600),
    ] {
        let path = root.path().join(name);
        fs::write(&path, record()).unwrap();
        owned(&path, uid, mode);
    }
    let lock = sibling(&root.path().join("readonly/pins"));
    fs::write(&lock, b"existing account lock").unwrap();
    owned(&lock, UID, 0o600);
    let lock = sibling(&root.path().join("account/unsafe-lock"));
    fs::write(&lock, b"wrong owner lock").unwrap();
    owned(&lock, 0, 0o600);
    fs::hard_link(
        root.path().join("external"),
        root.path().join("account/public-hardlink"),
    )
    .unwrap();
    symlink("../external", root.path().join("account/public-alias")).unwrap();
    symlink("../external", root.path().join("account/foreign-alias")).unwrap();
    // Symlink ownership itself is authority; never follow it while changing owner.
    rustix::fs::chownat(
        rustix::fs::CWD,
        root.path().join("account/foreign-alias"),
        Some(rustix::process::Uid::from_raw(FOREIGN)),
        Some(rustix::process::Gid::from_raw(FOREIGN)),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
    let root_write = root.path().join("root-write");
    KnownHosts::open(root_write.clone())
        .pin("root.invalid", 22, &KEY)
        .unwrap();
    assert_eq!(
        (
            fs::metadata(&root_write).unwrap().uid(),
            fs::metadata(&root_write).unwrap().mode() & 0o7777
        ),
        (0, 0o600)
    );

    let mut output = tempfile::tempfile().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
        .env(ROLE, "1")
        .env("QSH_PIN_AUTHORITY_ROOT", root.path())
        .env("QSH_PIN_AUTHORITY_PARENT", std::process::id().to_string())
        .uid(UID)
        .gid(UID)
        .stdin(Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(output.try_clone().unwrap())
        .spawn()
        .unwrap();
    let mut owned_child = OwnedChild {
        child,
        terminal: false,
        lost_identity: false,
    };
    let status = owned_child.wait().unwrap();
    output.rewind().unwrap();
    let mut bytes = Vec::new();
    output.take(16385).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 16384, "child output exceeds fixture bound");
    let text = String::from_utf8_lossy(&bytes);
    assert!(status.success(), "owned QSH pin child failed: {text}");
    assert!(
        text.contains(
            "validated actual root/account/foreign QSH pin read and publication boundaries"
        ),
        "{text}"
    );
    assert!(text.contains("1 passed; 0 failed; 0 ignored;"), "{text}");
    assert_eq!(
        fs::read(sibling(&root.path().join("account/unsafe-lock"))).unwrap(),
        b"wrong owner lock"
    );
    println!("owned QSH pin account child completed and reaped");
}
