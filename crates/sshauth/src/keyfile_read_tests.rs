use super::*;
use std::io::Write;

const LIMIT: usize = 1024 * 1024;

fn text() -> String {
    PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap()
    .to_openssh(ssh_key::LineEnding::LF)
    .unwrap()
    .to_string()
}

fn padded(size: usize) -> String {
    let key = text();
    format!("{}{key}", " ".repeat(size - key.len()))
}

#[test]
fn private_key_read_accepts_exactly_one_mib() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(padded(LIMIT).as_bytes()).unwrap();
    assert!(read(file.path()).is_ok());
}

#[test]
fn private_key_read_rejects_one_byte_over_one_mib_without_secret_diagnostic() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(padded(LIMIT + 1).as_bytes()).unwrap();
    let error = read(file.path()).unwrap_err();
    assert!(error.to_string().contains("1 MiB"));
    assert!(!error.to_string().contains("PRIVATE KEY"));
}

#[cfg(unix)]
fn fifo_reader(
    path: &Path,
    hold: bool,
    reaped: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<std::process::ExitStatus> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    struct OwnedChild {
        child: Child,
        terminal: bool,
        lost_identity: bool,
        reaped: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
                        self.reaped.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(error) => {
                        if !reported {
                            eprintln!("private-key FIFO fixture retains child custody after wait error: {error}");
                            reported = true;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
    }
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "keyfile::read_tests::private_key_read_refuses_fifo_instead_of_reading_a_key_from_it",
            "--nocapture",
        ])
        .env("QSH_KEYFILE_FIFO_CHILD", path)
        .env("QSH_KEYFILE_FIFO_HOLD", if hold { "1" } else { "0" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut owned = OwnedChild {
        child,
        terminal: false,
        lost_identity: false,
        reaped: std::sync::Arc::clone(reaped),
    };
    let until = Instant::now() + Duration::from_secs(2);
    let mut supplied = false;
    loop {
        match owned.child.try_wait() {
            Ok(Some(status)) => {
                owned.terminal = true;
                reaped.store(true, Ordering::SeqCst);
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                owned.lost_identity = error.raw_os_error() == Some(libc::ECHILD);
                return Err(error);
            }
        }
        if !hold && !supplied {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
            {
                Ok(mut writer) => {
                    // Releases the OLD blocking reader. NEW rejection may race
                    // this write and close first; its child status is decisive.
                    let _ = writer.write_all(text().as_bytes());
                    supplied = true;
                }
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                Err(error) => return Err(error),
            }
        }
        if Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned FIFO reader did not settle",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(unix)]
#[test]
fn private_key_read_refuses_fifo_instead_of_reading_a_key_from_it() {
    if let Some(path) = std::env::var_os("QSH_KEYFILE_FIFO_CHILD") {
        let path = std::path::PathBuf::from(path);
        if std::env::var("QSH_KEYFILE_FIFO_HOLD").as_deref() == Ok("1") {
            std::fs::write(path.with_extension("entered"), b"1").unwrap();
            let _file = std::fs::File::open(&path).unwrap();
            panic!("held FIFO open unexpectedly returned without a writer");
        }
        let Err(error) = read(&path) else {
            panic!("FIFO was accepted as a private key");
        };
        assert!(error.to_string().contains("regular file"));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = fifo_reader(&path, false, &reaped);
    assert!(reaped.load(std::sync::atomic::Ordering::SeqCst));
    assert!(
        result.unwrap().success(),
        "owned reader must refuse the FIFO"
    );
}

#[cfg(unix)]
#[test]
fn private_key_read_fifo_timeout_reaps_the_owned_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = fifo_reader(&path, true, &reaped);
    assert!(
        reaped.load(std::sync::atomic::Ordering::SeqCst),
        "timeout must complete its actual owned wait"
    );
    assert!(
        path.with_extension("entered").exists(),
        "child reached its held open phase"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn private_key_read_bounds_growth_after_descriptor_metadata() {
    use std::io::Read;
    struct GrowingFile {
        file: std::fs::File,
        writer: std::fs::File,
        grew: bool,
        bytes_read: usize,
    }
    impl Read for GrowingFile {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.grew {
                self.grew = true;
                self.writer.write_all(&vec![b' '; LIMIT + 32])?;
            }
            let count = self.file.read(buffer)?;
            self.bytes_read += count;
            Ok(count)
        }
    }
    let mut temp = tempfile::NamedTempFile::new().unwrap();
    temp.write_all(b"x").unwrap();
    let file = temp.reopen().unwrap();
    assert!(file.metadata().unwrap().is_file());
    assert_eq!(file.metadata().unwrap().len(), 1);
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(temp.path())
        .unwrap();
    let mut growing = GrowingFile {
        file,
        writer,
        grew: false,
        bytes_read: 0,
    };
    let Err(error) = read_bounded(&mut growing) else {
        panic!("growing input exceeded the budget but was accepted");
    };
    assert!(error.to_string().contains("1 MiB"));
    assert_eq!(
        growing.bytes_read,
        LIMIT + 1,
        "read the overflow sentinel, not the remaining file"
    );
}

#[cfg(unix)]
#[test]
fn private_key_read_preserves_explicit_links_and_file_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let alias = dir.path().join("identity");
    std::fs::write(&target, text()).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
    symlink("target", &alias).unwrap();
    assert!(
        read(&alias).is_ok(),
        "this slice must not tighten existing trust policy"
    );
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o666
    );
}

#[cfg(unix)]
#[test]
fn private_key_read_rejects_directory_socket_and_device() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    for path in [
        dir.path(),
        socket.as_path(),
        std::path::Path::new("/dev/null"),
    ] {
        assert!(read_text(path).is_err());
    }
}

#[test]
fn private_key_read_uses_one_fixed_destination_through_the_sentinel() {
    struct FixedDestination {
        remaining: usize,
        used: usize,
        base: Option<usize>,
        calls: usize,
    }
    impl io::Read for FixedDestination {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert_eq!(
                buffer.len(),
                LIMIT + 1 - self.used,
                "fixed remaining read budget"
            );
            let base = (buffer.as_ptr() as usize).checked_sub(self.used).unwrap();
            if let Some(expected) = self.base {
                assert!(base == expected, "read destination must not move");
            } else {
                self.base = Some(base);
            }
            self.calls += 1;
            let count = self.remaining.min(buffer.len()).min(8191);
            buffer[..count].fill(b'x');
            self.remaining -= count;
            self.used += count;
            Ok(count)
        }
    }
    for size in [0, 17, LIMIT, LIMIT + 32] {
        let mut reader = FixedDestination {
            remaining: size,
            used: 0,
            base: None,
            calls: 0,
        };
        let result = read_bounded(&mut reader);
        assert_eq!(reader.used, size.min(LIMIT + 1));
        assert!(reader.calls > 0);
        if size <= LIMIT {
            assert_eq!(result.unwrap().len(), size);
        } else {
            assert!(
                matches!(result, Err(KeyFileError::Io(ref e)) if e.kind() == io::ErrorKind::InvalidData)
            );
            assert_eq!(reader.remaining, 31, "no read beyond the overflow sentinel");
        }
    }
}

#[test]
fn private_key_read_retries_interrupted_and_preserves_split_utf8() {
    struct InterruptedChunks {
        step: usize,
    }
    impl io::Read for InterruptedChunks {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let result = match self.step {
                0 | 2 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                1 => {
                    buffer[0] = 0xc3;
                    Ok(1)
                }
                3 => {
                    buffer[0] = 0xa9;
                    Ok(1)
                }
                _ => Ok(0),
            };
            self.step += 1;
            result
        }
    }
    let mut reader = InterruptedChunks { step: 0 };
    assert_eq!(&**read_bounded(&mut reader).unwrap(), "é");
    assert_eq!(reader.step, 5);
}

#[test]
fn private_key_read_errors_do_not_disclose_a_partial_prefix() {
    struct PartialFailure {
        read: bool,
    }
    impl io::Read for PartialFailure {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.read {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            self.read = true;
            buffer[..16].copy_from_slice(b"synthetic-secret");
            Ok(16)
        }
    }
    let error = read_bounded(&mut PartialFailure { read: false }).unwrap_err();
    assert!(
        matches!(error, KeyFileError::Io(ref e) if e.kind() == io::ErrorKind::PermissionDenied)
    );
    assert!(!error.to_string().contains("synthetic-secret"));
    let mut invalid = io::Cursor::new(b"synthetic-secret\xff");
    let error = read_bounded(&mut invalid).unwrap_err();
    assert!(matches!(error, KeyFileError::Io(ref e) if e.kind() == io::ErrorKind::InvalidData));
    assert!(!error.to_string().contains("synthetic-secret"));
    assert_eq!(invalid.position(), 17);
}
