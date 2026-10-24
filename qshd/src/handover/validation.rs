//! Structural checks on inherited raw handles and cooperative update paths.
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use nix::fcntl::{fcntl, FcntlArg};

use super::Handover;

pub(super) fn validate_number(fd: RawFd) -> Result<()> {
    if fd <= 2 {
        bail!("handover descriptor must be above stderr");
    }
    fcntl(fd, FcntlArg::F_GETFD).context("handover descriptor is not open")?;
    Ok(())
}

fn socket_option(fd: RawFd, option: nix::libc::c_int) -> Result<nix::libc::c_int> {
    let mut value: nix::libc::c_int = 0;
    let mut len = std::mem::size_of_val(&value) as nix::libc::socklen_t;
    // SAFETY: value and len point to initialized, correctly sized output storage.
    let result = unsafe {
        nix::libc::getsockopt(
            fd,
            nix::libc::SOL_SOCKET,
            option,
            (&mut value as *mut nix::libc::c_int).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("inspecting inherited socket");
    }
    if len as usize != std::mem::size_of_val(&value) {
        bail!("invalid inherited socket option length");
    }
    Ok(value)
}

fn socket_address(fd: RawFd) -> Result<(nix::libc::sockaddr_storage, usize)> {
    // SAFETY: zero is valid initialization for sockaddr_storage.
    let mut address: nix::libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&address) as nix::libc::socklen_t;
    // SAFETY: address is aligned, writable storage of exactly the supplied size.
    if unsafe {
        nix::libc::getsockname(
            fd,
            (&mut address as *mut nix::libc::sockaddr_storage).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("reading inherited socket address");
    }
    if len as usize > std::mem::size_of_val(&address) {
        bail!("invalid inherited socket address length");
    }
    Ok((address, len as usize))
}

#[cfg(not(target_os = "macos"))]
fn is_control_listener(fd: RawFd) -> Result<bool> {
    Ok(socket_option(fd, nix::libc::SO_ACCEPTCONN)? == 1)
}

#[cfg(target_os = "macos")]
fn is_control_listener(fd: RawFd) -> Result<bool> {
    extern "C" {
        fn qsh_handover_unix_listener_state(fd: nix::libc::c_int) -> nix::libc::c_int;
    }
    // SAFETY: the SDK-compiled adapter accepts only a descriptor number,
    // reads this process's kernel socket metadata, and returns 0/1 or -errno.
    match unsafe { qsh_handover_unix_listener_state(fd) } {
        0 => Ok(false),
        1 => Ok(true),
        error if error < 0 => Err(std::io::Error::from_raw_os_error(-error))
            .context("inspecting inherited control listener state with proc_pidfdinfo"),
        _ => bail!("invalid inherited control listener state result"),
    }
}

pub(super) fn validate_sockets(h: &Handover) -> Result<()> {
    validate_number(h.udp_fd)?;
    validate_number(h.control_fd)?;
    if socket_option(h.udp_fd, nix::libc::SO_TYPE)? != nix::libc::SOCK_DGRAM {
        bail!("inherited UDP socket is not a datagram socket");
    }
    let (udp, len) = socket_address(h.udp_fd)?;
    let port = match udp.ss_family as i32 {
        nix::libc::AF_INET if len >= std::mem::size_of::<nix::libc::sockaddr_in>() => {
            // SAFETY: family and returned length establish an IPv4 address.
            u16::from_be(unsafe { *(&udp as *const _ as *const nix::libc::sockaddr_in) }.sin_port)
        }
        nix::libc::AF_INET6 if len >= std::mem::size_of::<nix::libc::sockaddr_in6>() => {
            // SAFETY: family and returned length establish an IPv6 address.
            u16::from_be(unsafe { *(&udp as *const _ as *const nix::libc::sockaddr_in6) }.sin6_port)
        }
        _ => bail!("inherited UDP socket is not an Internet socket"),
    };
    if port == 0 || port != h.port {
        bail!("inherited UDP socket port does not match the handover");
    }
    if socket_option(h.control_fd, nix::libc::SO_TYPE)? != nix::libc::SOCK_STREAM
        || !is_control_listener(h.control_fd)?
    {
        bail!("inherited control socket is not a stream listener");
    }
    let (address, len) = socket_address(h.control_fd)?;
    if address.ss_family as i32 != nix::libc::AF_UNIX {
        bail!("inherited control socket is not a Unix socket");
    }
    let offset = std::mem::offset_of!(nix::libc::sockaddr_un, sun_path);
    if len <= offset || len > std::mem::size_of::<nix::libc::sockaddr_un>() {
        bail!("inherited control socket has no pathname");
    }
    // SAFETY: the AF_UNIX result contains len initialized bytes in address;
    // the pathname begins at the platform's sockaddr_un.sun_path offset.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&address as *const _ as *const u8).add(offset),
            len - offset,
        )
    };
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let bound = Path::new(std::ffi::OsStr::from_bytes(bytes));
    // bind_private publishes by rename. Its kernel address retains .c<pid>/s,
    // where pid belongs to the pre-daemonization parent, not necessarily us.
    let staging = bound.parent().context("control bind path has no parent")?;
    let name = staging.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let digits = name.strip_prefix(".c").unwrap_or("");
    if bound.file_name() != Some(std::ffi::OsStr::new("s"))
        || digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || staging.parent().map(std::fs::canonicalize).transpose()?
            != Some(std::fs::canonicalize(&h.cache_dir)?)
        || h.control_path != h.cache_dir.join("control.sock")
    {
        bail!("inherited control publication does not match its private bind path");
    }
    if !std::fs::symlink_metadata(&h.control_path)?
        .file_type()
        .is_socket()
    {
        bail!("inherited control publication is not a socket");
    }
    Ok(())
}

pub(super) fn validate_paths(h: &Handover) -> Result<()> {
    for path in [
        &h.binary_path,
        &h.staged_path,
        &h.cache_dir,
        &h.control_path,
    ] {
        if !path.is_absolute()
            || path
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .any(|part| part == b"." || part == b"..")
        {
            bail!("handover paths must be absolute without dot or parent components");
        }
    }
    let destination = h.binary_path.parent().context("binary has no parent")?;
    let source = h
        .staged_path
        .parent()
        .context("staged binary has no parent")?;
    let name = h
        .staged_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let prefix = format!(".qshd-update-{}-", std::process::id());
    if std::fs::canonicalize(destination)? != std::fs::canonicalize(source)?
        || !name.strip_prefix(&prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        })
        || h.binary_path.file_name().is_none()
    {
        bail!("handover replacement paths do not match a sibling staged update");
    }
    let staged = std::fs::symlink_metadata(&h.staged_path)?;
    if !staged.file_type().is_file() {
        bail!("staged update is not a regular file");
    }
    #[cfg(target_os = "linux")]
    let executable =
        std::fs::metadata("/proc/self/exe").context("inspecting the running executable")?;
    #[cfg(not(target_os = "linux"))]
    let executable =
        std::fs::metadata(std::env::current_exe()?).context("inspecting the running executable")?;
    if staged.dev() != executable.dev() || staged.ino() != executable.ino() {
        bail!("staged update is not the running executable");
    }
    match std::fs::symlink_metadata(&h.binary_path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("replacement destination is not a regular file")
        }
        Ok(metadata) if metadata.dev() == staged.dev() && metadata.ino() == staged.ino() => {
            bail!("replacement destination aliases the staged executable")
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("inspecting replacement destination"),
    }
    Ok(())
}
