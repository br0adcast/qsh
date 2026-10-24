//! Owned process fixtures; root-only tiers run only in disposable containers.
use super::*;
use std::io::Read;
use std::os::unix::fs::{symlink, DirBuilderExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const CASE: &str = "QSH_TEST_HOSTKEY_OWNED_CASE";
const FIXTURE: &str = "QSH_TEST_HOSTKEY_OWNED_DIR";
const PROBE: &str = "host_key::trusted::owned_tests::owned_probe";
// Deliberate noncredential filesystem payload, not a working keypair.
const BYTES: [u8; 64] = [23; 64];

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn private_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn key(path: &Path, mode: u32) {
    std::fs::write(path, BYTES).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}
fn owner(path: &Path, uid: u32, link: bool) {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let result = unsafe {
        if link {
            nix::libc::lchown(name.as_ptr(), uid, uid)
        } else {
            nix::libc::chown(name.as_ptr(), uid, uid)
        }
    };
    assert_eq!(result, 0, "owned fixture chown");
}
fn run(case: &str, dir: &Path, uid: Option<u32>) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", PROBE, "--nocapture", "--test-threads=1"])
        .env(CASE, case)
        .env(FIXTURE, dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir)
        .env("XDG_CACHE_HOME", dir)
        .env("HISTFILE", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(uid) = uid {
        let parent = unsafe { nix::libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if nix::libc::setgroups(0, std::ptr::null()) != 0
                    || nix::libc::setgid(uid) != 0
                    || nix::libc::setuid(uid) != 0
                    || nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if nix::libc::getppid() != parent {
                    return Err(io::Error::other("owned parent ended"));
                }
                Ok(())
            });
        }
    }
    let mut child = Owned(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "owned host-key probe deadline ({case})"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .take(32769)
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .take(32769)
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stdout.len() <= 32768 && stderr.len() <= 32768);
    Output {
        status,
        stdout,
        stderr,
    }
}
fn passed(result: Output) {
    assert!(
        result.status.success(),
        "owned probe: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
#[derive(Default)]
struct Observe {
    reads: usize,
}
impl ReadIo for Observe {
    fn read(&mut self, file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        file.read(buffer)
    }
}

#[test]
fn fifo_is_refused_without_blocking_open_or_reading_bytes() {
    let dir = private_dir();
    passed(run("fifo", dir.path(), None));
}

#[test]
fn loader_success_warning_describes_only_a_verified_repair() {
    let dir = private_dir();
    passed(run("warning", dir.path(), None));
}

#[test]
fn owned_probe() {
    let Some(case) = std::env::var_os(CASE) else {
        return;
    };
    let path = Path::new(&std::env::var_os(FIXTURE).unwrap()).to_owned();
    match case.to_str().unwrap() {
        "fifo" => {
            let fifo = path.join("fifo");
            nix::unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
            let mut io = Observe::default();
            let error = read(&fifo, Uid::effective(), &mut io).err().unwrap();
            assert!(error.to_string().contains("not a regular file"));
            assert_eq!(io.reads, 0);
            assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
        }
        "warning" => {
            crate::log::init(&path.join("log"));
            let key_path = path.join("key");
            key(&key_path, 0o644);
            crate::load_or_create_transport_key(&key_path).unwrap();
            let text = std::fs::read_to_string(path.join("log/qshd.log")).unwrap();
            assert!(text.contains("verified file permissions tightened to 0600"));
            assert!(text.contains("cannot undo a possible past disclosure"));
            assert_eq!(std::fs::metadata(key_path).unwrap().mode() & 0o777, 0o600);
        }
        "root" => root_tier(&path),
        "nonroot" => nonroot_tier(&path),
        "readonly" => {
            let key_path = path.join("key");
            let mut io = Observe::default();
            let error = read(&key_path, Uid::effective(), &mut io).err().unwrap();
            assert_eq!(io.reads, 0);
            assert_eq!(error.kind(), io::ErrorKind::ReadOnlyFilesystem);
            assert!(error
                .to_string()
                .contains("repairing verified host key permissions"));
            assert_eq!(std::fs::metadata(&key_path).unwrap().mode() & 0o777, 0o644);
            assert_eq!(std::fs::read(&key_path).unwrap(), BYTES);
            let log_dir = private_dir();
            crate::log::init(log_dir.path());
            assert!(crate::load_or_create_transport_key(&key_path).is_err());
            assert!(!std::fs::read_to_string(log_dir.path().join("qshd.log"))
                .unwrap()
                .contains("tightened"));
        }
        other => panic!("unknown owned host-key case: {other}"),
    }
}

fn root_tier(path: &Path) {
    assert_eq!(Uid::effective().as_raw(), 0, "disposable root fixture only");
    let dir = private_dir();
    let root = dir.path();
    let key_path = root.join("root.key");
    key(&key_path, 0o600);
    assert_eq!(
        read(&key_path, Uid::effective(), &mut FileIo)
            .unwrap()
            .bytes,
        BYTES
    );
    // With DAC override deliberately absent, readable fixture bytes let open
    // succeed so this proves the stricter metadata owner refusal, not EACCES.
    std::fs::set_permissions(&key_path, Permissions::from_mode(0o644)).unwrap();
    owner(&key_path, 65534, false);
    let mut io = Observe::default();
    assert!(read(&key_path, Uid::effective(), &mut io)
        .err()
        .unwrap()
        .to_string()
        .contains("untrusted owner"));
    assert_eq!(io.reads, 0);
    let unsafe_parent = root.join("other-owned");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&unsafe_parent)
        .unwrap();
    key(&unsafe_parent.join("key"), 0o600);
    owner(&unsafe_parent, 65534, false);
    assert!(read(&unsafe_parent.join("key"), Uid::effective(), &mut io)
        .err()
        .unwrap()
        .to_string()
        .contains("parent has an untrusted owner"));
    let alias = root.join("other-alias");
    symlink(&unsafe_parent, &alias).unwrap();
    owner(&alias, 65534, true);
    assert!(read(&alias.join("key"), Uid::effective(), &mut io)
        .err()
        .unwrap()
        .to_string()
        .contains("alias has an untrusted owner"));
    assert_eq!(io.reads, 0);

    // Restore only this fixture directory so its owned cleanup can traverse it.
    owner(&unsafe_parent, 0, false);

    // Nonroot reader can traverse trusted root parents/aliases, but must refuse
    // a world-readable root-owned leaf BEFORE reading or attempting repair.
    std::fs::set_permissions(root, Permissions::from_mode(0o755)).unwrap();
    key(&root.join("foreign.key"), 0o644);
    key(&root.join("personal.key"), 0o644);
    owner(&root.join("personal.key"), 65534, false);
    symlink(root, root.join("trusted-alias")).unwrap();
    passed(run("nonroot", root, Some(65534)));
    assert_eq!(
        std::fs::metadata(root.join("foreign.key")).unwrap().mode() & 0o777,
        0o644
    );
    assert_eq!(
        std::fs::metadata(root.join("personal.key")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(path.exists()); // external fixture is retained through all child joins
}
fn nonroot_tier(root: &Path) {
    assert_eq!(Uid::effective().as_raw(), 65534);
    let mut io = Observe::default();
    assert!(read(&root.join("foreign.key"), Uid::effective(), &mut io)
        .err()
        .unwrap()
        .to_string()
        .contains("untrusted owner"));
    assert_eq!(io.reads, 0);
    let loaded = read(
        &root.join("trusted-alias/personal.key"),
        Uid::effective(),
        &mut io,
    )
    .unwrap();
    assert_eq!(loaded.bytes, BYTES);
    assert_eq!(loaded.repaired_mode, Some(0o644));
    assert!(io.reads > 0);
}
