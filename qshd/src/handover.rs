//! Handing a running personal daemon's state to the binary that replaces it
//! in the same process (spec §4.4, §4.5).
//!
//! The old process `exec`s the staged binary directly -- same pid, the file
//! at the binary's path untouched until the new process renames itself onto
//! it. What survives the `exec`: the UDP socket, the listening control
//! socket and a memory file holding the [`Handover`] description, whose
//! number travels in [`HANDOVER_FD_ENV`] -- close-on-exec cleared on exactly
//! those three, and only right before the `exec` (all three are created
//! with it set). Every other descriptor is marked close-on-exec first
//! -- a pseudo-terminal opened without the flag would otherwise leak into the
//! new binary and keep a dead session's shell alive.
//!
//! Live sessions (crypto state, pseudo-terminals) do not survive: the daemon
//! tells every client `Restarting` before it gets here.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
#[cfg(target_os = "linux")]
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use serde::{Deserialize, Serialize};

mod validation;
use validation::{validate_number, validate_paths, validate_sockets};

/// Names the descriptor of the memory file holding the [`Handover`].
pub const HANDOVER_FD_ENV: &str = "QSHD_HANDOVER_FD";

/// How many times an `exec` that met `ETXTBSY` is tried again, and how far
/// apart: about 1.5 s in all. That error means some thread of this process
/// forked while the staged file was still open for writing, and the child
/// has not reached its own `exec` yet; it usually passes in milliseconds,
/// but a loaded machine can stretch the gap.
pub(crate) const EXEC_ATTEMPTS: u32 = 30;
pub(crate) const EXEC_RETRY: Duration = Duration::from_millis(50);

/// What the replacing binary needs to go on being this daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handover {
    /// The format of this description (`crate::state::HANDOVER_VERSION` of
    /// the writer). A reader refuses one it does not list in
    /// `crate::state::ACCEPTED_HANDOVER_VERSIONS`.
    pub handover_version: u32,
    /// Where the binary lives: the new process renames itself onto it.
    pub binary_path: PathBuf,
    /// Where the new binary was staged, and is exec'd from.
    pub staged_path: PathBuf,
    pub udp_fd: RawFd,
    pub control_fd: RawFd,
    pub control_path: PathBuf,
    /// The daemon's cache directory: its log and its Noise key live there.
    pub cache_dir: PathBuf,
    pub port: u16,
    pub ports: Vec<u16>,
    pub name: String,
    /// Admitted client keys, base64 -- including the one-time ones
    /// `ADD-CLIENT` put there and nothing else remembers.
    pub allowlist: Vec<String>,
}

pub fn encode_allowlist(keys: &[[u8; 32]]) -> Vec<String> {
    keys.iter().map(|k| BASE64.encode(k)).collect()
}

pub fn decode_allowlist(keys: &[String]) -> Result<Vec<[u8; 32]>> {
    keys.iter()
        .map(|k| {
            let raw = BASE64.decode(k).context("an allowlist key is not base64")?;
            <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| anyhow::anyhow!("an allowlist key is {} bytes, not 32", raw.len()))
        })
        .collect()
}

/// Create an unnamed, close-on-exec file for the state passed across exec.
fn handover_file() -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        let fd = memfd_create(c"qshd-handover", MemFdCreateFlag::MFD_CLOEXEC)
            .context("creating the handover memory file")?;
        Ok(File::from(fd))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS has no memfd_create. tempfile opens with mode 0600 and
        // close-on-exec, then unlinks the file before returning its handle.
        tempfile::tempfile().context("creating the unnamed handover file")
    }
}

/// Write `handover` into a fresh unnamed file (a memory file on Linux).
///
/// The file is created close-on-exec, like every other descriptor this
/// daemon opens: a shell spawned while it exists must not inherit it. The
/// caller clears the flag only right before `exec`, together with the two
/// sockets (and puts it back if the `exec` fails).
pub fn write_memfd(handover: &Handover) -> Result<OwnedFd> {
    let json = serde_json::to_string(handover).context("serializing the handover")?;
    let mut file = handover_file()?;
    file.write_all(json.as_bytes())
        .context("writing the handover")?;
    file.seek(SeekFrom::Start(0))
        .context("rewinding the handover")?;
    Ok(OwnedFd::from(file))
}

/// Just the version of a handover description, read before the rest: a
/// description in a format this binary does not know is refused by its
/// version, whatever shape its other fields have.
#[derive(Deserialize)]
struct VersionProbe {
    handover_version: u32,
}

/// Read a handover back from its unnamed file, closing it.
pub fn read_handover(fd: OwnedFd) -> Result<Handover> {
    read_description(&mut File::from(fd))
}

fn read_description(file: &mut File) -> Result<Handover> {
    file.seek(SeekFrom::Start(0))
        .context("rewinding the handover")?;
    let mut json = String::new();
    file.read_to_string(&mut json)
        .context("reading the handover")?;
    let probe: VersionProbe =
        serde_json::from_str(&json).context("reading the handover's version")?;
    if !crate::state::ACCEPTED_HANDOVER_VERSIONS.contains(&probe.handover_version) {
        bail!(
            "handover version {} is not one this binary reads ({:?})",
            probe.handover_version,
            crate::state::ACCEPTED_HANDOVER_VERSIONS
        );
    }
    serde_json::from_str(&json).context("parsing the handover")
}

/// A validated, single-use transfer from the cooperative daemon this image
/// replaced. Numeric descriptor fields are only a serialized description;
/// socket ownership lives here and cannot be adopted a second time.
#[derive(Debug)]
pub struct PreparedHandover {
    description: Handover,
    socket: UdpSocket,
    listener: UnixListener,
    allowlist: Vec<[u8; 32]>,
}

impl PreparedHandover {
    pub fn description(&self) -> &Handover {
        &self.description
    }

    pub fn settle_binary(&self) -> Result<()> {
        settle_binary(&self.description)
    }

    pub fn into_parts(self) -> (Handover, UdpSocket, UnixListener, Vec<[u8; 32]>) {
        (self.description, self.socket, self.listener, self.allowlist)
    }
}

/// Read and validate inherited state before opening logs or renaming files.
/// Call once, at startup, before starting threads or opening other descriptors.
/// The cooperative old daemon remains the authority for the destination name
/// and the renamed control publication; this does not authenticate a hostile
/// same-UID producer of descriptors or JSON.
///
/// # Safety
///
/// Each descriptor accepted by validation must be exclusively available for
/// ownership transfer: no other Rust owner may own its number. Callers must
/// prevent concurrent descriptor changes throughout this function. Kernel
/// validation can reject malformed input, but cannot prove these ownership
/// preconditions. A fresh exec image, before any descriptor opens or threads,
/// provides them for the cooperative parent's inherited descriptors.
pub unsafe fn take_from_env() -> Result<Option<PreparedHandover>> {
    let Some(raw) = std::env::var_os(HANDOVER_FD_ENV) else {
        return Ok(None);
    };
    std::env::remove_var(HANDOVER_FD_ENV);
    let fd: RawFd = raw
        .to_str()
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("{HANDOVER_FD_ENV} is not a descriptor number"))?;
    validate_number(fd)?;
    let stat = nix::sys::stat::fstat(fd).context("inspecting the handover file")?;
    if stat.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG || stat.st_nlink != 0 {
        bail!("handover descriptor is not an anonymous regular file");
    }
    if fcntl(fd, FcntlArg::F_GETFL)? & nix::libc::O_ACCMODE == nix::libc::O_WRONLY {
        bail!("handover file is not readable");
    }
    // SAFETY: startup is single-threaded; kernel checks established a live
    // inherited file above stdio. No other owner has been created in this image.
    let mut file = unsafe { File::from_raw_fd(fd) };
    set_cloexec(fd, true)?;
    let description = read_description(&mut file)?;
    if description.udp_fd == description.control_fd
        || description.udp_fd == fd
        || description.control_fd == fd
    {
        bail!("handover descriptors must be distinct");
    }
    validate_sockets(&description)?;
    validate_paths(&description)?;
    let allowlist = decode_allowlist(&description.allowlist)?;
    // Validate everything before transferring either socket. If a flag update
    // fails after transfer, the two unique owners close the accepted pair.
    // SAFETY: both live inherited descriptors have different numbers and
    // disjoint kernel roles, and neither has an owner in this fresh image.
    let socket = unsafe { UdpSocket::from_raw_fd(description.udp_fd) };
    let listener = unsafe { UnixListener::from_raw_fd(description.control_fd) };
    set_cloexec(socket.as_raw_fd(), true)?;
    set_cloexec(listener.as_raw_fd(), true)?;
    Ok(Some(PreparedHandover {
        description,
        socket,
        listener,
        allowlist,
    }))
}

pub fn set_cloexec(fd: RawFd, on: bool) -> nix::Result<()> {
    let flags = FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD)?);
    let flags = if on {
        flags | FdFlag::FD_CLOEXEC
    } else {
        flags - FdFlag::FD_CLOEXEC
    };
    fcntl(fd, FcntlArg::F_SETFD(flags))?;
    Ok(())
}

pub fn is_cloexec(fd: RawFd) -> nix::Result<bool> {
    Ok(FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD)?).contains(FdFlag::FD_CLOEXEC))
}

/// Mark every open descriptor above stderr close-on-exec, except `keep`.
///
/// Only `EBADF` is tolerated -- a descriptor closed between the listing and
/// the `fcntl` (the listing's own descriptor always is). Any other failure
/// is returned: a descriptor left without the flag, a pseudo-terminal say,
/// would silently leak into the new image.
pub fn close_on_exec_except(keep: &[RawFd]) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let directory = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let directory = "/dev/fd";
    let mut fds = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        {
            fds.push(fd);
        }
    }
    mark_close_on_exec(fds, keep, |fd| set_cloexec(fd, true))
}

/// The sweep behind [`close_on_exec_except`], with the flag setter passed
/// in so its error handling can be tested without a real failing `fcntl`.
pub(crate) fn mark_close_on_exec(
    fds: impl IntoIterator<Item = RawFd>,
    keep: &[RawFd],
    mut set: impl FnMut(RawFd) -> nix::Result<()>,
) -> std::io::Result<()> {
    for fd in fds {
        if fd <= 2 || keep.contains(&fd) {
            continue;
        }
        match set(fd) {
            Ok(()) | Err(Errno::EBADF) => {}
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::Error::from(e).kind(),
                    format!("marking descriptor {fd} close-on-exec: {e}"),
                ))
            }
        }
    }
    Ok(())
}

/// `exec` the staged binary with this process's environment plus
/// [`HANDOVER_FD_ENV`]. Returns only on failure. The caller clears
/// close-on-exec on the handed-over descriptors right before this and puts
/// it back if this returns.
pub fn exec_staged(staged: &Path, handover_fd: RawFd) -> Errno {
    let Ok(path) = CString::new(staged.as_os_str().as_bytes()) else {
        return Errno::EINVAL;
    };
    let argv = [c"qshd".to_owned(), c"transport-resume".to_owned()];
    let mut env: Vec<CString> = std::env::vars_os()
        .filter(|(key, _)| key != HANDOVER_FD_ENV)
        .filter_map(|(key, value)| {
            let mut pair = key.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(value.as_bytes());
            CString::new(pair).ok()
        })
        .collect();
    env.push(
        CString::new(format!("{HANDOVER_FD_ENV}={handover_fd}")).expect("a number has no NUL byte"),
    );
    exec_with_retries(
        || match nix::unistd::execve(&path, &argv, &env) {
            Ok(never) => match never {},
            Err(e) => e,
        },
        EXEC_ATTEMPTS,
        EXEC_RETRY,
    )
}

/// Call `exec` (which returns only its error) up to `attempts` times,
/// `pause` apart, for as long as it answers `ETXTBSY`; return the first
/// other answer, or `ETXTBSY` after the last attempt.
pub(crate) fn exec_with_retries(
    mut exec: impl FnMut() -> Errno,
    attempts: u32,
    pause: Duration,
) -> Errno {
    let mut attempt = 1;
    loop {
        match exec() {
            Errno::ETXTBSY if attempt < attempts => {
                attempt += 1;
                std::thread::sleep(pause);
            }
            e => return e,
        }
    }
}

/// Rename the staged binary onto the binary's path and flush the directory,
/// so the rename survives a power cut. `rename` keeps the inode: from here
/// `/proc/self/exe` names the permanent path.
fn settle_binary(handover: &Handover) -> Result<()> {
    std::fs::rename(&handover.staged_path, &handover.binary_path).with_context(|| {
        format!(
            "renaming {} onto {}",
            handover.staged_path.display(),
            handover.binary_path.display()
        )
    })?;
    if let Some(dir) = handover.binary_path.parent() {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("flushing {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fd_flags_lock;
    use std::os::fd::AsRawFd;

    fn sample() -> Handover {
        Handover {
            handover_version: crate::state::HANDOVER_VERSION,
            binary_path: PathBuf::from("/home/u/.cache/qsh/qshd"),
            staged_path: PathBuf::from("/home/u/.cache/qsh/.qshd-update-1-0"),
            udp_fd: 5,
            control_fd: 6,
            control_path: PathBuf::from("/home/u/.cache/qsh/control.sock"),
            cache_dir: PathBuf::from("/home/u/.cache/qsh"),
            port: 60001,
            ports: vec![60001, 60000],
            name: "main".to_string(),
            allowlist: encode_allowlist(&[[1; 32], [2; 32]]),
        }
    }

    #[test]
    fn a_handover_survives_a_trip_through_a_memory_file() {
        let _fds = fd_flags_lock();
        let fd = write_memfd(&sample()).expect("memfd");
        assert!(
            is_cloexec(fd.as_raw_fd()).unwrap(),
            "the memory file is close-on-exec until the caller clears it right before exec"
        );
        let file = File::from(fd);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            file.metadata().unwrap().nlink(),
            0,
            "no named state file remains"
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(file.metadata().unwrap().mode() & 0o077, 0);
        assert_eq!(
            read_handover(OwnedFd::from(file)).expect("read back"),
            sample()
        );
    }

    /// A description in a format this binary cannot read is refused rather
    /// than half-understood. The running daemon checks this before it execs
    /// (the staged binary's self-check lists what it accepts); this is the
    /// last line of defense on the other side.
    #[test]
    fn a_handover_of_an_unknown_version_is_refused() {
        let _fds = fd_flags_lock();
        let fd = write_memfd(&Handover {
            handover_version: 99,
            ..sample()
        })
        .expect("memfd");
        let err = read_handover(fd).expect_err("an unknown version");
        assert!(format!("{err:#}").contains("99"), "{err:#}");
    }

    #[test]
    fn cloexec_can_be_cleared_and_set_again() {
        let _fds = fd_flags_lock();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        assert!(
            is_cloexec(fd).unwrap(),
            "std opens every socket close-on-exec"
        );
        set_cloexec(fd, false).unwrap();
        assert!(!is_cloexec(fd).unwrap());
        set_cloexec(fd, true).unwrap();
        assert!(is_cloexec(fd).unwrap());
    }

    /// Before exec, every descriptor but the handed-over ones is closed on
    /// exec -- a pseudo-terminal left without the flag would otherwise leak
    /// into the new binary and keep a dead session's shell alive.
    #[test]
    fn every_other_descriptor_is_marked_close_on_exec() {
        let _fds = fd_flags_lock();
        let kept = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let other = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        set_cloexec(kept.as_raw_fd(), false).unwrap();
        set_cloexec(other.as_raw_fd(), false).unwrap();
        close_on_exec_except(&[kept.as_raw_fd()]).unwrap();
        assert!(!is_cloexec(kept.as_raw_fd()).unwrap());
        assert!(is_cloexec(other.as_raw_fd()).unwrap());
        set_cloexec(kept.as_raw_fd(), true).unwrap();
    }

    #[test]
    fn settling_renames_the_staged_file_onto_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("qshd");
        let staged = dir.path().join(".qshd-update-1-0");
        std::fs::write(&binary, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let handover = Handover {
            binary_path: binary.clone(),
            staged_path: staged.clone(),
            ..sample()
        };
        settle_binary(&handover).expect("rename");
        assert_eq!(std::fs::read(&binary).unwrap(), b"new");
        assert!(!staged.exists());
    }

    #[test]
    fn the_allowlist_travels_as_base64_and_a_bad_entry_is_refused() {
        let keys = [[7u8; 32], [9u8; 32]];
        assert_eq!(
            decode_allowlist(&encode_allowlist(&keys)).unwrap(),
            keys.to_vec()
        );
        assert!(decode_allowlist(&["not base64!".to_string()]).is_err());
        assert!(
            decode_allowlist(&["AAAA".to_string()]).is_err(),
            "three bytes are no key"
        );
    }

    /// An exec that cannot happen returns its error; this can never replace
    /// the test process, because there is nothing at the path to run.
    #[test]
    fn an_exec_of_a_missing_file_returns_its_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = exec_staged(&dir.path().join("absent"), 0);
        assert_eq!(err, nix::errno::Errno::ENOENT);
    }
    /// The version is read before anything else: a description from a
    /// newer writer whose other fields changed shape is refused by its
    /// version, not by a confusing parse error about some field.
    #[test]
    fn an_unknown_version_is_refused_before_the_rest_is_parsed() {
        let _fds = fd_flags_lock();
        let mut file = handover_file().unwrap();
        file.write_all(br#"{"handover_version":99,"udp_fd":{"not":"a number"}}"#)
            .unwrap();
        let err = read_handover(OwnedFd::from(file)).expect_err("an unknown version");
        let message = format!("{err:#}");
        assert!(message.contains("handover version 99"), "{message}");
    }

    #[test]
    fn a_descriptor_closed_mid_sweep_is_skipped_but_any_other_failure_is_returned() {
        let mut touched = Vec::new();
        mark_close_on_exec([0, 1, 2, 3, 4, 5], &[4], |fd| {
            touched.push(fd);
            Err(Errno::EBADF)
        })
        .expect("EBADF only means the descriptor is already gone");
        assert_eq!(
            touched,
            vec![3, 5],
            "stdio and kept descriptors are left alone"
        );

        let err = mark_close_on_exec([3, 5, 6], &[], |fd| match fd {
            5 => Err(Errno::EPERM),
            _ => Ok(()),
        })
        .expect_err("a descriptor that could not be marked would leak into the new image");
        assert!(err.to_string().contains('5'), "{err}");
    }

    #[test]
    fn an_exec_that_meets_a_busy_file_is_tried_again_until_another_answer() {
        let mut calls = 0;
        let err = exec_with_retries(
            || {
                calls += 1;
                if calls < 3 {
                    Errno::ETXTBSY
                } else {
                    Errno::ENOENT
                }
            },
            EXEC_ATTEMPTS,
            Duration::ZERO,
        );
        assert_eq!(err, Errno::ENOENT);
        assert_eq!(calls, 3);
    }

    #[test]
    fn an_exec_that_stays_busy_gives_up_after_the_last_attempt() {
        let mut calls = 0;
        let err = exec_with_retries(
            || {
                calls += 1;
                Errno::ETXTBSY
            },
            EXEC_ATTEMPTS,
            Duration::ZERO,
        );
        assert_eq!(err, Errno::ETXTBSY);
        assert_eq!(calls, EXEC_ATTEMPTS);
    }

    #[test]
    fn the_retries_add_up_to_about_one_and_a_half_seconds() {
        assert_eq!(
            EXEC_RETRY * (EXEC_ATTEMPTS - 1),
            Duration::from_millis(1450)
        );
    }
}
