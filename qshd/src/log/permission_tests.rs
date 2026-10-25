use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Instant;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

fn set_private(file: &File) -> io::Result<()> {
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

fn owned_open(path: &Path, apply: impl FnOnce(&File) -> io::Result<()>) -> io::Result<File> {
    super::super::open_log_file_with(path, nix::unistd::Uid::effective().as_raw(), apply)
}

// Only this new selfexec fixture uses this custodian. Its directory and output
// stay owned until an exact terminal wait; an observed ECHILD forbids signals.
struct LogChild {
    child: Child,
    root: tempfile::TempDir,
    terminal: bool,
    lost_wait: bool,
}

impl LogChild {
    fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.terminal = true;
                Ok(Some(status))
            }
            Err(error) => {
                self.lost_wait |= error.raw_os_error() == Some(nix::libc::ECHILD);
                Err(error)
            }
            result => result,
        }
    }

    fn finish(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.poll() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => return Err(io::ErrorKind::TimedOut.into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for LogChild {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        let mut signaled = false;
        let mut reported = false;
        loop {
            match self.poll() {
                Ok(Some(_)) => return,
                Ok(None) if !self.lost_wait && !signaled => {
                    let _ = self.child.kill();
                    signaled = true;
                }
                Err(error) if !reported => {
                    eprintln!("retaining exact log fixture child after wait error: {error}");
                    reported = true;
                }
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn log280_private_creation_and_safe_aliases() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    let stdout = File::create(&output).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "log::tests::permissions::private_creation_body",
            "--exact",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "--color=never",
        ])
        .env("HOME", root.path())
        .env("XDG_CACHE_HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .env("HISTFILE", "/dev/null")
        .env("QSHD_LOG280_ROOT", root.path())
        .stdout(Stdio::from(stdout.try_clone().unwrap()))
        .stderr(Stdio::from(stdout))
        .spawn()
        .unwrap();
    let mut owned = LogChild {
        child,
        root,
        terminal: false,
        lost_wait: false,
    };
    let status = owned.finish().expect("exact log fixture wait");
    let mut text = String::new();
    File::open(owned.root.path().join("output"))
        .unwrap()
        .take(65_537)
        .read_to_string(&mut text)
        .unwrap();
    assert!(text.len() <= 65_536, "bounded fixture output");
    assert!(status.success(), "{status}: {text}");
    assert!(text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    assert!(text.contains("validated private creation before descriptor preparation"));
}

#[test]
#[ignore = "owned permissive-umask subprocess of the ordinary creation control"]
fn private_creation_body() {
    let root = std::path::PathBuf::from(std::env::var_os("QSHD_LOG280_ROOT").unwrap());
    nix::sys::stat::umask(nix::sys::stat::Mode::empty());
    let path = root.join("new-log");
    let file = owned_open(&path, |file| {
        assert_eq!(
            file.metadata()?.mode() & 0o7777,
            0o600,
            "private at creation"
        );
        set_private(file)
    })
    .unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);

    // With no FIFO reader, a blocking append-open would stall before type
    // validation. This runs under the parent's exact-child deadline.
    let unread_fifo = root.join("unread-fifo");
    nix::unistd::mkfifo(
        &unread_fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let no_reader = owned_open(&unread_fifo, |_| panic!("FIFO permission mutation")).unwrap_err();
    assert_eq!(no_reader.raw_os_error(), Some(nix::libc::ENXIO));

    let target = root.join("target");
    fs::write(&target, b"existing\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
    let alias = root.join("alias");
    let hardlink = root.join("hardlink");
    std::os::unix::fs::symlink("target", &alias).unwrap();
    fs::hard_link(&target, &hardlink).unwrap();
    let before = fs::metadata(&target).unwrap();
    let parent_mode = mode(&root);
    for route in [&alias, &hardlink] {
        let mut logger = Logger::open(route.clone(), root.join("rotation"), 128).unwrap();
        logger.write_text("accepted\n");
        assert_eq!(logger.file.metadata().unwrap().ino(), before.ino());
    }
    assert_eq!(mode(&root), parent_mode);
    assert!(fs::symlink_metadata(&alias).unwrap().is_symlink());
    assert_eq!(fs::metadata(&target).unwrap().nlink(), before.nlink());
    assert_eq!(mode(&target), 0o600);
    assert_eq!(
        fs::read(&target).unwrap(),
        b"existing\naccepted\naccepted\n"
    );
    println!("validated private creation before descriptor preparation");
}

#[test]
fn log280_permission_failures_refuse_initial_and_rotated_sinks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("current");
    let rotated = dir.path().join("previous");
    let initial = Logger::open_with(path.clone(), rotated.clone(), 16, |path| {
        owned_open(path, |_| {
            Err(io::Error::from_raw_os_error(nix::libc::EACCES))
        })
    });
    let initial_errno = initial.as_ref().err().and_then(io::Error::raw_os_error);
    drop(initial);
    assert_eq!(fs::read(&path).unwrap(), b"");
    let mut logger = Logger::open(path.clone(), rotated.clone(), 16).unwrap();
    logger.write_text("before\n");
    let rotated_refused = !logger.rotate_with(|path| {
        owned_open(path, |_| {
            Err(io::Error::from_raw_os_error(nix::libc::EACCES))
        })
    });
    assert_eq!(
        (initial_errno, rotated_refused),
        (Some(nix::libc::EACCES), true),
        "permission failure must refuse both initial and rotated sinks"
    );
    assert!(logger.pending_open);
    assert_eq!(fs::read(&rotated).unwrap(), b"before\n");
    assert_eq!(fs::read(&path).unwrap(), b"");
    logger.write_text("after\n");
    assert!(!logger.pending_open);
    assert!(!logger.rotation_failed);
    assert_eq!(fs::read(&rotated).unwrap(), b"before\n");
    assert_eq!(fs::read(&path).unwrap(), b"after\n");
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn log280_path_replacement_cannot_redirect_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("current");
    let displaced = dir.path().join("held");
    fs::write(&path, b"original\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let mut logger = Logger::open_with(path.clone(), dir.path().join("previous"), 128, |path| {
        owned_open(path, |file| {
            fs::rename(path, &displaced)?;
            fs::write(path, b"replacement sentinel\n")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
            super::super::apply_log_permissions(file)
        })
    })
    .unwrap();
    logger.write_text("held append\n");
    assert_eq!(mode(&path), 0o644, "replacement must not receive chmod");
    assert_eq!(fs::read(&path).unwrap(), b"replacement sentinel\n");
    assert_eq!(mode(&displaced), 0o600);
    assert_eq!(fs::read(&displaced).unwrap(), b"original\nheld append\n");
    assert_eq!(
        logger.file.metadata().unwrap().ino(),
        fs::metadata(displaced).unwrap().ino()
    );
}

#[test]
fn log280_unsuitable_or_unconfirmed_held_files_are_not_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o644)).unwrap();
    fs::set_permissions(&fifo, fs::Permissions::from_mode(0o644)).unwrap();
    let _holder = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let mut called = false;
    let result = owned_open(&fifo, |_| {
        called = true;
        Ok(())
    });
    assert!(result.is_err(), "FIFO cannot become the file sink");
    assert!(!called, "type check precedes permission mutation");
    assert_eq!(mode(&fifo), 0o644);
    assert!(owned_open(dir.path(), set_private).is_err());

    let file = dir.path().join("regular");
    fs::write(&file, b"unchanged").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        owned_open(&file, |_| Ok(())).is_err(),
        "ineffective permissions refused"
    );
    assert_eq!(mode(&file), 0o644);
    let actual_owner = fs::metadata(&file).unwrap().uid();
    let different_owner = if actual_owner == 0 { 1 } else { 0 };
    let mut owner_callback = false;
    let result = super::super::open_log_file_with(&file, different_owner, |held| {
        owner_callback = true;
        set_private(held)
    });
    assert!(
        result.is_err(),
        "modeled different expected UID must refuse"
    );
    assert!(!owner_callback, "owner check precedes permission mutation");
    assert_eq!(mode(&file), 0o644);
    assert_eq!(fs::read(&file).unwrap(), b"unchanged");
}
