//! Private staging and exclusive rename in one verified directory.
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;

use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use rand_core::{OsRng, RngCore};

pub(super) struct Stage {
    pub file: File,
    pub name: CString,
}

pub(super) fn create(parent: &File) -> io::Result<Stage> {
    create_with(parent, || {
        let mut random = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(io::Error::other)?;
        Ok(CString::new(format!(
            ".qshd-host-key-{:032x}",
            u128::from_ne_bytes(random)
        ))
        .unwrap())
    })
}

fn create_with(parent: &File, mut name: impl FnMut() -> io::Result<CString>) -> io::Result<Stage> {
    for _ in 0..32 {
        let name = name()?;
        match openat(
            Some(parent.as_raw_fd()),
            name.as_c_str(),
            OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ) {
            // SAFETY: openat returned a new, uniquely owned descriptor.
            Ok(fd) => {
                return Ok(Stage {
                    file: unsafe { File::from_raw_fd(fd) },
                    name,
                })
            }
            Err(nix::errno::Errno::EEXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "host key staging name collision limit reached",
    ))
}

pub(super) fn remove(parent: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: owned parent and NUL-terminated name remain live during unlinkat.
    if unsafe { nix::libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn rename(parent: &File, stage: &CStr, leaf: &std::ffi::OsStr) -> io::Result<()> {
    let leaf = CString::new(leaf.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in host key name"))?;
    // SAFETY: both names are NUL-terminated and relative to the held directory.
    // There is deliberately no link/unlink fallback: the visible key must have
    // exactly one link, including while another creator loads the winner.
    #[cfg(target_os = "linux")]
    let result = unsafe {
        // Use the kernel operation directly: some supported musl toolchains
        // declare renameat2 but do not export its libc wrapper symbol.
        nix::libc::syscall(
            nix::libc::SYS_renameat2,
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
            nix::libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_vendor = "apple")]
    let result = unsafe {
        nix::libc::renameatx_np(
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
            nix::libc::RENAME_EXCL,
        )
    };
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic exclusive host key rename is unsupported on this platform",
    ));
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
