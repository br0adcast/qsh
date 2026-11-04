//! Owned master descriptor and the post-creation custody boundary.
use portable_pty::{MasterPty, PtySize};
use std::cell::Cell;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use transport::channel_open::{OpenCustody, SpawnFailure, UninstalledChannel};
use transport::channel_server::ChannelWait;
use transport::shell_server::SessionScreen;

pub(super) struct Master {
    file: File,
    writer_taken: Cell<bool>,
}
impl Master {
    pub fn new(file: File) -> Self {
        Self {
            file,
            writer_taken: Cell::new(false),
        }
    }
}
impl MasterPty for Master {
    fn resize(&self, size: PtySize) -> anyhow::Result<()> {
        let dimensions = nix::libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };
        if unsafe { nix::libc::ioctl(self.file.as_raw_fd(), nix::libc::TIOCSWINSZ, &dimensions) }
            < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn get_size(&self) -> anyhow::Result<PtySize> {
        let mut value: nix::libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { nix::libc::ioctl(self.file.as_raw_fd(), nix::libc::TIOCGWINSZ, &mut value) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(PtySize {
            rows: value.ws_row,
            cols: value.ws_col,
            pixel_width: value.ws_xpixel,
            pixel_height: value.ws_ypixel,
        })
    }
    fn try_clone_reader(&self) -> anyhow::Result<Box<dyn Read + Send>> {
        Ok(Box::new(MasterReader(self.file.try_clone()?)))
    }
    fn take_writer(&self) -> anyhow::Result<Box<dyn Write + Send>> {
        if self.writer_taken.replace(true) {
            anyhow::bail!("keeper PTY writer was already taken");
        }
        Ok(Box::new(MasterWriter(self.file.try_clone()?)))
    }
    fn process_group_leader(&self) -> Option<nix::libc::pid_t> {
        let pgid = unsafe { nix::libc::tcgetpgrp(self.file.as_raw_fd()) };
        (pgid > 0).then_some(pgid)
    }
    fn as_raw_fd(&self) -> Option<i32> {
        Some(self.file.as_raw_fd())
    }
    fn tty_name(&self) -> Option<std::path::PathBuf> {
        None
    }
}

#[derive(Clone)]
pub(super) enum Startup {
    Pending,
    Ready,
    Failed(String),
}
/// This value exists only after the original S child and every control endpoint
/// have transferred to `wait`. Its private fields prevent caller-side splitting.
pub(super) struct Created {
    guard: transport::channel_open::ConstructionGuard,
    master: Box<dyn MasterPty + Send>,
    startup: Startup,
    #[cfg(target_os = "macos")]
    driver: Option<super::keeper::StartupDriver>,
    custody: OpenCustody,
}
impl Created {
    pub fn new(
        master: Box<dyn MasterPty + Send>,
        wait: Box<dyn ChannelWait>,
        startup: Startup,
        custody: &OpenCustody,
        screen: Box<dyn SessionScreen>,
    ) -> Self {
        let guard = custody.protect(wait, screen);
        Self {
            guard,
            master,
            startup,
            #[cfg(target_os = "macos")]
            driver: None,
            custody: custody.clone(),
        }
    }
    #[cfg(target_os = "macos")]
    fn driven(
        master: Box<dyn MasterPty + Send>,
        wait: Box<dyn ChannelWait>,
        driver: super::keeper::StartupDriver,
        custody: &OpenCustody,
        screen: Box<dyn SessionScreen>,
    ) -> Self {
        let mut created = Self::new(master, wait, Startup::Pending, custody, screen);
        created.driver = Some(driver);
        created
    }
    #[cfg(target_os = "macos")]
    fn fail(&mut self, reason: &str) {
        if let Some(driver) = &self.driver {
            driver.fail();
        }
        self.startup = Startup::Failed(reason.to_owned());
    }
    #[cfg(all(test, target_os = "macos"))]
    pub fn fixture_authority(&self) -> Option<super::keeper::FixtureAuthority> {
        self.driver.as_ref().map(|driver| driver.fixture())
    }
    #[cfg(all(test, target_os = "macos"))]
    pub fn fixture_master_fd(&self) -> Option<i32> {
        self.master.as_raw_fd()
    }
    pub fn finish(self) -> Result<UninstalledChannel, SpawnFailure> {
        let construction = self.guard;
        let master = self.master;
        let custody = self.custody;
        let startup = self.startup;
        #[cfg(target_os = "macos")]
        let startup = match self.driver {
            Some(driver) => driver.complete(&custody),
            None => startup,
        };
        match startup {
            Startup::Failed(reason) => return Err(custody.failure(reason)),
            Startup::Pending => return Err(custody.failure("keeper startup is incomplete".into())),
            Startup::Ready => {}
        }
        let reader = master
            .try_clone_reader()
            .map_err(|_| custody.failure("keeper PTY reader is unavailable".into()))?;
        let writer = master
            .take_writer()
            .map_err(|_| custody.failure("keeper PTY writer is unavailable".into()))?;
        Ok(construction.finish(
            reader,
            writer,
            Box::new(crate::pty::PtyResizeHandle::new(master)),
        ))
    }
}

struct MasterWriter(File);
impl Write for MasterWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
impl Drop for MasterWriter {
    fn drop(&mut self) {
        // Match the existing portable PTY writer's configured EOF behavior.
        let mut settings: nix::libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { nix::libc::tcgetattr(self.0.as_raw_fd(), &mut settings) } == 0 {
            let eof = settings.c_cc[nix::libc::VEOF];
            if eof != 0 {
                let _ = self.0.write_all(&[b'\n', eof]);
            }
        }
    }
}

/// Temporary reservations never overwrite an existing parent descriptor. The
/// caller serializes standard-FD closure throughout preparation and spawn.
pub(super) struct StandardReservations {
    _files: Vec<File>,
}
impl StandardReservations {
    pub fn acquire() -> std::io::Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let mut files = Vec::new();
        for _ in 0..3 {
            let mut missing = false;
            for fd in 0..3 {
                if unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(nix::libc::EBADF) {
                        return Err(error);
                    }
                    missing = true;
                }
            }
            if !missing {
                return Ok(Self { _files: files });
            }
            // open chooses a vacant slot; it cannot overwrite a caller's FD.
            files.push(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(nix::libc::O_CLOEXEC)
                    .open("/dev/null")?,
            );
        }
        if !(0..3).all(|fd| unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0) {
            return Err(std::io::ErrorKind::Other.into());
        }
        Ok(Self { _files: files })
    }
}

#[cfg(target_os = "macos")]
pub(super) enum ImageSource {
    Current,
    #[cfg(test)]
    Fixture {
        path: std::path::PathBuf,
        sha256: String,
    },
}
#[cfg(target_os = "macos")]
struct VerifiedImage {
    path: std::path::PathBuf,
    _file: File,
    metadata: ImageMetadata,
}
#[cfg(target_os = "macos")]
#[derive(PartialEq, Eq)]
struct ImageMetadata {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
#[cfg(target_os = "macos")]
impl ImageMetadata {
    fn get(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}
#[cfg(target_os = "macos")]
impl ImageSource {
    fn verify(self, end: std::time::Instant) -> Result<VerifiedImage, String> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let (path, expected) = match self {
            Self::Current => (
                super::native::keeper_image_path()
                    .map_err(|_| "keeper source image is unavailable")?,
                crate::state::self_checksum()
                    .map_err(|_| "keeper source checksum is unavailable")?,
            ),
            #[cfg(test)]
            Self::Fixture { path, sha256 } => (path, sha256),
        };
        if !path.is_absolute()
            || expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("keeper source binding is invalid".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| "keeper source image cannot be opened")?;
        let before = file
            .metadata()
            .map_err(|_| "keeper source metadata is unavailable")?;
        if !before.is_file()
            || before.len() == 0
            || before.len() > 512 * 1024 * 1024
            || before.permissions().mode() & 0o111 == 0
        {
            return Err("keeper source image is inadmissible".into());
        }
        let key = ImageMetadata::get(&before);
        let mut hasher = Sha256::new();
        let mut remaining = before.len();
        let mut buffer = [0; 64 * 1024];
        while remaining > 0 {
            if std::time::Instant::now() >= end {
                return Err("keeper startup deadline expired".into());
            }
            let count = remaining.min(buffer.len() as u64) as usize;
            let n = file
                .read(&mut buffer[..count])
                .map_err(|_| "keeper source image cannot be read")?;
            if n == 0 {
                return Err("keeper source image changed".into());
            }
            hasher.update(&buffer[..n]);
            remaining -= n as u64;
        }
        if std::time::Instant::now() >= end
            || hex::encode(hasher.finalize()) != expected
            || ImageMetadata::get(
                &file
                    .metadata()
                    .map_err(|_| "keeper source metadata is unavailable")?,
            ) != key
        {
            return Err("keeper source image changed".into());
        }
        let verified = VerifiedImage {
            path,
            _file: file,
            metadata: key,
        };
        verified.recheck()?;
        Ok(verified)
    }
}
#[cfg(target_os = "macos")]
impl VerifiedImage {
    fn recheck(&self) -> Result<(), String> {
        let current =
            std::fs::symlink_metadata(&self.path).map_err(|_| "keeper source path changed")?;
        if !current.is_file() || ImageMetadata::get(&current) != self.metadata {
            return Err("keeper source path changed".into());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl super::keeper::KeeperOwner {
    /// A non-default constructor. Every post-creation result is already protected
    /// by the caller's one fresh, registered OpenCustody before it is returned.
    pub(super) fn spawn(
        image: ImageSource,
        command: Option<&[u8]>,
        size: PtySize,
        term: Option<&str>,
        end: std::time::Instant,
        custody: &OpenCustody,
        screen: Box<dyn SessionScreen>,
    ) -> Result<Created, SpawnFailure> {
        use super::keeper_helper::{Channel, Launch, ENTRY};
        use rand_core::RngCore;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::CommandExt;
        let before = |reason: &str| custody.refuse_before_creation(reason.to_owned());
        let reservations = StandardReservations::acquire()
            .map_err(|_| before("keeper standard descriptors cannot be reserved"))?;
        let admission = super::native::keeper_prepare()
            .map_err(|_| before("keeper process ownership is unavailable"))?;
        let image = image.verify(end).map_err(|reason| before(&reason))?;
        if size.rows == 0 || size.cols == 0 {
            return Err(before("keeper terminal size is invalid"));
        }
        let argv = match command {
            Some(bytes) if bytes.len() <= transport::channel::MAX_COMMAND_LEN => {
                crate::channel_backend::split_command(bytes)
                    .map_err(|_| before("keeper command is invalid"))?
            }
            Some(_) => return Err(before("keeper command is too long")),
            None => vec![std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())],
        };
        let mut instance = [0; 16];
        rand_core::OsRng
            .try_fill_bytes(&mut instance)
            .map_err(|_| before("keeper instance could not be allocated"))?;
        if instance == [0; 16] {
            return Err(before("keeper instance could not be allocated"));
        }
        let mut environment = vec![(
            "TERM".to_owned(),
            term.unwrap_or(crate::pty::TERM_VALUE).to_owned(),
        )];
        if let Some((key, value)) = crate::pty::utf8_locale_env() {
            environment.push((key.to_owned(), value.to_owned()));
        }
        let launch = Launch { argv, environment }
            .encode(instance)
            .map_err(|_| before("keeper launch metadata is invalid"))?;
        let dimensions = nix::pty::Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };
        let pair = nix::pty::openpty(Some(&dimensions), None)
            .map_err(|_| before("keeper pseudo-terminal is unavailable"))?;
        for fd in [pair.master.as_raw_fd(), pair.slave.as_raw_fd()] {
            let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
            if fd < 3
                || flags < 0
                || unsafe {
                    nix::libc::fcntl(fd, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC)
                } < 0
            {
                return Err(before("keeper pseudo-terminal descriptor is invalid"));
            }
        }
        let master = Master::new(File::from(pair.master));
        if command.is_some() {
            crate::pty::disable_echo(&master)
                .map_err(|_| before("keeper terminal echo cannot be prepared"))?;
        }
        let (qs, sq) =
            UnixStream::pair().map_err(|_| before("keeper session channel is unavailable"))?;
        let (qb, bq) =
            UnixStream::pair().map_err(|_| before("keeper broker channel is unavailable"))?;
        let sfd = sq.as_raw_fd();
        let bfd = bq.as_raw_fd();
        let slave = pair.slave.as_raw_fd();
        if sfd < 3 || bfd < 3 || sfd == bfd || sfd == slave || bfd == slave {
            return Err(before("keeper inherited descriptors are invalid"));
        }
        let qs = Channel::new(qs, instance)
            .map_err(|_| before("keeper session channel cannot be prepared"))?;
        let qb = Channel::new(qb, instance)
            .map_err(|_| before("keeper broker channel cannot be prepared"))?;
        let mut executable = std::process::Command::new(&image.path);
        executable
            .arg(ENTRY)
            .arg(std::process::id().to_string())
            .arg(sfd.to_string())
            .arg(bfd.to_string())
            .arg(hex::encode(instance));
        // All three descriptors remain occupied and owned while std allocates
        // its separate exec-error pipe. Only the child clears inherited flags.
        unsafe {
            executable.pre_exec(move || super::native::keeper_pre_exec(slave, sfd, bfd));
        }
        let permit = crate::update::spawn_permit();
        image.recheck().map_err(|reason| before(&reason))?;
        if std::time::Instant::now() >= end {
            return Err(before("keeper startup deadline expired"));
        }
        let session = executable
            .spawn()
            .map_err(|_| before("keeper session could not be executed"))?;
        let (owner, driver) = Self::created(session, qs, qb, launch, end, admission);
        let mut created =
            Created::driven(Box::new(master), Box::new(owner), driver, custody, screen);
        // The permit still excludes our updater here; any observed source drift
        // is recorded only after protection, never returned as a bare Err.
        if image.recheck().is_err() {
            created.fail("keeper source image changed after creation");
        }
        drop(permit);
        drop(pair.slave);
        drop(sq);
        drop(bq);
        drop(reservations);
        Ok(created)
    }
}

pub(super) fn master_read_result(result: std::io::Result<usize>) -> std::io::Result<usize> {
    match result {
        Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => Ok(0),
        other => other,
    }
}
struct MasterReader(File);
impl Read for MasterReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        master_read_result(self.0.read(buffer))
    }
}
