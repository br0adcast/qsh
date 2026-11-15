//! Operation-owned executable staging, without service authorization.
//!
//! Callers supply handles opened through their trusted, no-follow ancestry policy.
//! Reexec and adoption belong to a single-threaded internal entrypoint, before
//! runtimes or concurrent child creation. Context and candidate identity describe
//! selected artifact bytes; neither proves the original process's executing image.

use crate::state::SelfCheck;
use base64::{engine::general_purpose::STANDARD, Engine};
use daemon_bootstrap_protocol::CandidateImageIdentity;
use nix::libc;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::ffi::{CString, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub const MAX_STAGE_IMAGE: u64 = 64 * 1024 * 1024;
pub const MAX_OPERATION_CONTEXT: usize = 16 * 1024;
pub const MAX_LAUNCH_CONTEXT: usize = 32 * 1024;
pub const LAUNCH_ENV: &str = "QSHD_SERVICE_STAGE_V1";
const LEAF: &str = "qshd";
// Darwin uses a narrower mode_t than Linux; metadata's mode is always u32.
#[allow(clippy::unnecessary_cast)]
const TYPE_MASK: u32 = libc::S_IFMT as u32;
#[allow(clippy::unnecessary_cast)]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR as u32;
#[allow(clippy::unnecessary_cast)]
const REGULAR_TYPE: u32 = libc::S_IFREG as u32;

#[derive(Debug)]
pub enum StageError {
    Invalid,
    Untrusted,
    Changed,
    TooLarge,
    CheckFailed,
    Io(io::Error),
}
impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid exposing operation contents or private routes through errors.
        match self {
            Self::Io(error) => write!(f, "stage I/O failed: {:?}", error.kind()),
            other => write!(f, "stage rejected: {other:?}"),
        }
    }
}
impl std::error::Error for StageError {}
impl From<io::Error> for StageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    len: u64,
    links: u64,
}
impl Identity {
    fn of(file: &File) -> Result<Self, StageError> {
        Ok(Self::metadata(&file.metadata()?))
    }
    fn metadata(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            mode: m.mode(),
            len: m.len(),
            links: m.nlink(),
        }
    }
    fn same_object(&self, other: &Self) -> bool {
        // Directory length/link count change as entries are added and removed.
        self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.mode == other.mode
    }
    fn directory(&self) -> bool {
        self.mode & TYPE_MASK == DIRECTORY_TYPE
            && self.mode & 0o7777 == 0o700
            && self.uid == effective_uid()
    }
    fn executable(&self) -> bool {
        self.mode & TYPE_MASK == REGULAR_TYPE
            && self.mode & 0o7777 == 0o500
            && self.uid == effective_uid()
            && self.links == 1
            && (1..=MAX_STAGE_IMAGE).contains(&self.len)
    }
}

pub struct StageRoot {
    directory: File,
    route: PathBuf,
    identity: Identity,
}
impl StageRoot {
    /// `directory` and its ancestry must already satisfy the caller's trust policy.
    pub fn from_trusted(directory: File, absolute_route: PathBuf) -> Result<Self, StageError> {
        if !valid_route(&absolute_route) {
            return Err(StageError::Invalid);
        }
        let identity = Identity::of(&directory)?;
        if !identity.directory() || !read_only(&directory)? {
            return Err(StageError::Untrusted);
        }
        cloexec(&directory)?;
        let root = Self {
            directory,
            route: absolute_route,
            identity,
        };
        root.revalidate()?;
        Ok(root)
    }
    pub fn revalidate(&self) -> Result<(), StageError> {
        let actual = Identity::of(&self.directory)?;
        let route = open_path(&self.route, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if !actual.directory()
            || !self.identity.same_object(&actual)
            || !self.identity.same_object(&Identity::of(&route)?)
        {
            return Err(StageError::Changed);
        }
        Ok(())
    }
}

struct Custody {
    root: StageRoot,
    directory: File,
    executable: Option<File>,
    stage_identity: Identity,
    image_identity: Option<Identity>,
    stage_name: String,
    path: PathBuf,
    cleanup: bool,
}
impl Custody {
    fn validate(&self, candidate: &CandidateImageIdentity) -> Result<(), StageError> {
        self.root.revalidate()?;
        let directory = open_at(
            &self.root.directory,
            &self.stage_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        let current = Identity::of(&self.directory)?;
        if !current.directory()
            || !self.stage_identity.same_object(&current)
            || !self.stage_identity.same_object(&Identity::of(&directory)?)
        {
            return Err(StageError::Changed);
        }
        let image = self.executable.as_ref().ok_or(StageError::Invalid)?;
        let expected = self.image_identity.as_ref().ok_or(StageError::Invalid)?;
        let actual = Identity::of(image)?;
        // Reject a substituted special file without waiting for a FIFO peer.
        let route = open_at(&self.directory, LEAF, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        if !actual.executable()
            || expected != &actual
            || expected != &Identity::of(&route)?
            || checksum(image)? != candidate.checksum.to_ascii_lowercase()
            || expected != &Identity::of(image)?
        {
            return Err(StageError::Changed);
        }
        Ok(())
    }
    fn remove(&mut self) -> Result<(), StageError> {
        if !self.cleanup {
            return Ok(());
        }
        self.root.revalidate()?;
        let directory = open_at(
            &self.root.directory,
            &self.stage_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        if !self.stage_identity.same_object(&Identity::of(&directory)?)
            || !self
                .stage_identity
                .same_object(&Identity::of(&self.directory)?)
        {
            return Err(StageError::Changed);
        }
        match open_at(&self.directory, LEAF, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(file) => {
                let actual = Identity::of(&file)?;
                // While preparing, mode may still be 0600; pin identity as soon as created.
                let expected = self.image_identity.as_ref().ok_or(StageError::Changed)?;
                if actual.dev != expected.dev
                    || actual.ino != expected.ino
                    || actual.uid != effective_uid()
                    || actual.mode & TYPE_MASK != REGULAR_TYPE
                {
                    return Err(StageError::Changed);
                }
                unlink_at(&self.directory, LEAF, 0)?;
            }
            Err(StageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        unlink_at(&self.root.directory, &self.stage_name, libc::AT_REMOVEDIR)?;
        self.cleanup = false;
        Ok(())
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

pub struct PreparedStage {
    custody: Custody,
    candidate: CandidateImageIdentity,
    operation: Vec<u8>,
}
impl PreparedStage {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        root: StageRoot,
        source: &mut File,
        candidate: CandidateImageIdentity,
        expected_arch: &str,
        expected_protocol: u8,
        operation: &[u8],
        self_check: impl FnOnce(&Path) -> Result<SelfCheck, String>,
    ) -> Result<Self, StageError> {
        check_binding(&candidate, operation)?;
        if expected_arch.is_empty() || expected_arch.len() > 128 {
            return Err(StageError::Invalid);
        }
        root.revalidate()?;
        let source_identity = Identity::of(source)?;
        if source_identity.len == 0 {
            return Err(StageError::Invalid);
        }
        if source_identity.len > MAX_STAGE_IMAGE {
            return Err(StageError::TooLarge);
        }
        if source_identity.mode & TYPE_MASK != REGULAR_TYPE
            || source_identity.mode & 0o022 != 0
            || source_identity.mode & 0o111 == 0
            || source_identity.mode & 0o7000 != 0
            || source_identity.links != 1
            || (source_identity.uid != effective_uid() && source_identity.uid != 0)
        {
            return Err(StageError::Untrusted);
        }
        let (stage_name, directory) = create_stage(&root)?;
        let stage_identity = Identity::of(&directory)?;
        let path = root.route.join(&stage_name).join(LEAF);
        let mut custody = Custody {
            root,
            directory,
            executable: None,
            stage_identity,
            image_identity: None,
            stage_name,
            path,
            cleanup: true,
        };
        let mut writable = open_at(
            &custody.directory,
            LEAF,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        custody.image_identity = Some(Identity::of(&writable)?);
        let digest = copy_image(source, &mut writable)?;
        if Identity::of(source)? != source_identity
            || digest != candidate.checksum.to_ascii_lowercase()
        {
            return Err(StageError::Changed);
        }
        writable.flush()?;
        writable.sync_all()?;
        writable.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        drop(writable); // No writable descriptor survives into self-check/exec.
        let image = open_at(
            &custody.directory,
            LEAF,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        let final_identity = Identity::of(&image)?;
        let created = custody.image_identity.as_ref().ok_or(StageError::Invalid)?;
        if !final_identity.executable()
            || final_identity.dev != created.dev
            || final_identity.ino != created.ino
        {
            return Err(StageError::Changed);
        }
        custody.image_identity = Some(final_identity);
        custody.executable = Some(image);
        custody.validate(&candidate)?;
        let check = self_check(&custody.path).map_err(|_| StageError::CheckFailed)?;
        if check.build != candidate.build
            || check.arch != expected_arch
            || !check.protocols.contains(&expected_protocol)
        {
            return Err(StageError::CheckFailed);
        }
        custody.validate(&candidate)?;
        Ok(Self {
            custody,
            candidate,
            operation: operation.to_vec(),
        })
    }
    pub fn executable(&self) -> &Path {
        &self.custody.path
    }
    pub fn validate(
        &self,
        candidate: &CandidateImageIdentity,
        operation: &[u8],
    ) -> Result<(), StageError> {
        check_binding(candidate, operation)?;
        if candidate != &self.candidate || operation != self.operation {
            return Err(StageError::Changed);
        }
        self.custody.validate(candidate)
    }
    /// Call only in the single-threaded internal launch entrypoint.
    pub fn reexec(self, args: &[OsString]) -> Result<Infallible, StageError> {
        if std::env::var_os(LAUNCH_ENV).is_some()
            || args.iter().any(|arg| {
                arg.as_bytes()
                    .windows(LAUNCH_ENV.len())
                    .any(|part| part == LAUNCH_ENV.as_bytes())
            })
        {
            return Err(StageError::Invalid);
        }
        self.validate(&self.candidate, &self.operation)?;
        let handles = [
            duplicate(&self.custody.root.directory)?,
            duplicate(&self.custody.directory)?,
            duplicate(
                self.custody
                    .executable
                    .as_ref()
                    .ok_or(StageError::Invalid)?,
            )?,
        ];
        let context = StageLaunchContext {
            version: 1,
            nonce: self.custody.stage_name[6..].to_owned(),
            root_route: self.custody.root.route.clone(),
            stage_name: self.custody.stage_name.clone(),
            root: self.custody.root.identity.clone(),
            directory: self.custody.stage_identity.clone(),
            executable: self
                .custody
                .image_identity
                .clone()
                .ok_or(StageError::Invalid)?,
            descriptors: handles.each_ref().map(|file| file.as_raw_fd()),
            candidate: self.candidate.clone(),
            operation: STANDARD.encode(&self.operation),
            operation_digest: hex::encode(Sha256::digest(&self.operation)),
        };
        let encoded = serde_json::to_string(&context).map_err(|_| StageError::Invalid)?;
        // Parse/check complete bounded metadata before making anything inheritable.
        StageLaunchContext::parse(&encoded)?;
        let executable = cstring(self.executable().as_os_str())?;
        let mut argv = vec![executable.clone()];
        for arg in args {
            argv.push(cstring(arg)?);
        }
        let mut environment = Vec::new();
        for (key, value) in std::env::vars_os() {
            let mut entry = key;
            entry.push("=");
            entry.push(value);
            environment.push(cstring(&entry)?);
        }
        environment.push(
            CString::new(format!("{LAUNCH_ENV}={encoded}")).map_err(|_| StageError::Invalid)?,
        );
        let mut argv_ptrs: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut env_ptrs: Vec<_> = environment.iter().map(|entry| entry.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());
        self.validate(&self.candidate, &self.operation)?;
        for file in &handles {
            set_cloexec(file, false)?;
        }
        // execve deliberately avoids execvp/Command's ENOEXEC shell fallback.
        unsafe {
            libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
        }
        let error = io::Error::last_os_error();
        // The explicit environment never changed this process's environment. All owned
        // duplicates close here, then the prepared stage removes its exact files.
        drop(handles);
        Err(StageError::Io(error))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageLaunchContext {
    version: u8,
    nonce: String,
    root_route: PathBuf,
    stage_name: String,
    root: Identity,
    directory: Identity,
    executable: Identity,
    descriptors: [i32; 3],
    candidate: CandidateImageIdentity,
    operation: String,
    operation_digest: String,
}
impl StageLaunchContext {
    pub fn parse(encoded: &str) -> Result<Self, StageError> {
        if encoded.len() > MAX_LAUNCH_CONTEXT {
            return Err(StageError::TooLarge);
        }
        let context: Self = serde_json::from_str(encoded).map_err(|_| StageError::Invalid)?;
        context.check_fields()?;
        Ok(context)
    }
    fn check_fields(&self) -> Result<(), StageError> {
        if self.version != 1
            || !lower_hex(&self.nonce, 32)
            || self.stage_name != format!("stage-{}", self.nonce)
            || !valid_route(&self.root_route)
            || !self.root.directory()
            || !self.directory.directory()
            || !self.executable.executable()
            || self.descriptors.iter().any(|fd| *fd < 3)
            || self.descriptors[0] == self.descriptors[1]
            || self.descriptors[0] == self.descriptors[2]
            || self.descriptors[1] == self.descriptors[2]
            || !lower_hex(&self.operation_digest, 64)
        {
            return Err(StageError::Invalid);
        }
        let operation = self.operation_bytes()?;
        check_binding(&self.candidate, &operation)?;
        Ok(())
    }
    fn operation_bytes(&self) -> Result<Vec<u8>, StageError> {
        if self.operation.len() > MAX_OPERATION_CONTEXT.div_ceil(3) * 4 {
            return Err(StageError::TooLarge);
        }
        let bytes = STANDARD
            .decode(&self.operation)
            .map_err(|_| StageError::Invalid)?;
        if bytes.len() > MAX_OPERATION_CONTEXT {
            return Err(StageError::TooLarge);
        }
        if STANDARD.encode(&bytes) != self.operation
            || hex::encode(Sha256::digest(&bytes)) != self.operation_digest
        {
            return Err(StageError::Changed);
        }
        Ok(bytes)
    }
}

pub struct AdoptedStage {
    custody: Custody,
    candidate: CandidateImageIdentity,
    operation: Vec<u8>,
}
impl AdoptedStage {
    /// The integration entrypoint must remove LAUNCH_ENV first and independently
    /// recheck trusted ancestry and service authority. No descriptor is consumed
    /// on rejection; only fully validated inherited descriptors close on success.
    pub fn adopt(
        context: StageLaunchContext,
        candidate: &CandidateImageIdentity,
        operation: &[u8],
    ) -> Result<Self, StageError> {
        context.check_fields()?;
        check_binding(candidate, operation)?;
        if candidate != &context.candidate || operation != context.operation_bytes()? {
            return Err(StageError::Changed);
        }
        let expected = [&context.root, &context.directory, &context.executable];
        // fstat and access-mode checks precede ownership/duplication. Raw numbers
        // are borrowed only; failed validation never closes caller descriptors.
        for (fd, identity) in context.descriptors.iter().zip(expected) {
            let actual = raw_identity(*fd)?;
            if !identity.same_object(&actual)
                || (identity.executable() && identity != &actual)
                || !raw_read_only(*fd)?
            {
                return Err(StageError::Changed);
            }
        }
        let root_file = duplicate_raw(context.descriptors[0])?;
        let directory = duplicate_raw(context.descriptors[1])?;
        let image = duplicate_raw(context.descriptors[2])?;
        let root = StageRoot::from_trusted(root_file, context.root_route)?;
        let mut custody = Custody {
            path: root.route.join(&context.stage_name).join(LEAF),
            root,
            directory,
            executable: Some(image),
            stage_identity: context.directory,
            image_identity: Some(context.executable),
            stage_name: context.stage_name,
            cleanup: false,
        };
        custody.validate(candidate)?;
        for fd in context.descriptors {
            // Validated above and retained by our own copies; this is an internal
            // single-threaded ownership transfer, never a public fd-close API.
            unsafe {
                libc::close(fd);
            }
        }
        custody.cleanup = true;
        Ok(Self {
            custody,
            candidate: candidate.clone(),
            operation: operation.to_vec(),
        })
    }
    pub fn validate(
        &self,
        candidate: &CandidateImageIdentity,
        operation: &[u8],
    ) -> Result<(), StageError> {
        check_binding(candidate, operation)?;
        if candidate != &self.candidate || operation != self.operation {
            return Err(StageError::Changed);
        }
        self.custody.validate(candidate)
    }
    pub fn operation(&self) -> &[u8] {
        &self.operation
    }
    /// The daemonization parent transfers cleanup to its fork child before drop.
    pub fn disarm_cleanup(&mut self) {
        self.custody.cleanup = false;
    }
    pub fn cleanup(mut self) -> Result<(), StageError> {
        self.custody.remove()
    }
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn check_binding(candidate: &CandidateImageIdentity, operation: &[u8]) -> Result<(), StageError> {
    if operation.len() > MAX_OPERATION_CONTEXT {
        return Err(StageError::TooLarge);
    }
    if !candidate.valid() {
        return Err(StageError::Invalid);
    }
    Ok(())
}
fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_route(path: &Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some()
        && path.as_os_str().as_bytes().len() <= 4096
        && path
            .components()
            .all(|p| matches!(p, Component::RootDir | Component::Normal(_)))
        && !path.as_os_str().as_bytes().contains(&0)
}
fn cstring(path: &std::ffi::OsStr) -> Result<CString, StageError> {
    CString::new(path.as_bytes()).map_err(|_| StageError::Invalid)
}
fn open_path(path: &Path, flags: i32) -> Result<File, StageError> {
    let path = cstring(path.as_os_str())?;
    owned_fd(unsafe { libc::open(path.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) })
}
fn open_at(parent: &File, leaf: &str, flags: i32, mode: libc::mode_t) -> Result<File, StageError> {
    let leaf = CString::new(leaf).map_err(|_| StageError::Invalid)?;
    owned_fd(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    })
}
fn owned_fd(fd: RawFd) -> Result<File, StageError> {
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // Only freshly allocated open/dup results enter ownership here.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn duplicate(file: &File) -> Result<File, StageError> {
    duplicate_raw(file.as_raw_fd())
}
fn duplicate_raw(fd: RawFd) -> Result<File, StageError> {
    owned_fd(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })
}
// libc stat field widths vary across Linux/Darwin; retain lossless common DTO widths.
#[allow(clippy::unnecessary_cast)]
fn raw_identity(fd: RawFd) -> Result<Identity, StageError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    Ok(Identity {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
        uid: stat.st_uid,
        mode: stat.st_mode as u32,
        len: stat.st_size.try_into().map_err(|_| StageError::Invalid)?,
        links: stat.st_nlink as u64,
    })
}
fn raw_read_only(fd: RawFd) -> Result<bool, StageError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(flags & libc::O_ACCMODE == libc::O_RDONLY)
}
fn read_only(file: &File) -> Result<bool, StageError> {
    raw_read_only(file.as_raw_fd())
}
fn cloexec(file: &File) -> Result<(), StageError> {
    set_cloexec(file, true)
}
fn set_cloexec(file: &File, enabled: bool) -> Result<(), StageError> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error().into());
    }
    let flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn create_stage(root: &StageRoot) -> Result<(String, File), StageError> {
    for _ in 0..32 {
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| StageError::Invalid)?;
        let name = format!("stage-{}", hex::encode(nonce));
        let c_name = CString::new(name.as_str()).map_err(|_| StageError::Invalid)?;
        if unsafe { libc::mkdirat(root.directory.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(error.into());
        }
        let directory = open_at(
            &root.directory,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        if !Identity::of(&directory)?.directory() {
            return Err(StageError::Untrusted);
        }
        return Ok((name, directory));
    }
    Err(StageError::Changed)
}
fn unlink_at(parent: &File, leaf: &str, flags: i32) -> Result<(), StageError> {
    let leaf = CString::new(leaf).map_err(|_| StageError::Invalid)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn copy_image(source: &File, target: &mut File) -> Result<String, StageError> {
    image_digest(source, |bytes| target.write_all(bytes))
}
fn checksum(source: &File) -> Result<String, StageError> {
    image_digest(source, |_| Ok(()))
}
fn image_digest(
    source: &File,
    mut consume: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<String, StageError> {
    let mut buffer = [0; 64 * 1024];
    let mut offset = 0;
    let mut hash = Sha256::new();
    loop {
        let count = match source.read_at(&mut buffer, offset) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        offset += count as u64;
        if offset > MAX_STAGE_IMAGE {
            return Err(StageError::TooLarge);
        }
        hash.update(&buffer[..count]);
        consume(&buffer[..count])?;
    }
    if offset == 0 {
        return Err(StageError::Invalid);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
#[path = "service_stage_tests.rs"]
mod tests;
