use crate::wire::{Record, BYTES};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
pub fn now() -> io::Result<u64> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } < 0 {
        return Err(io::Error::last_os_error());
    }
    (t.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|x| x.checked_add(t.tv_nsec as u64))
        .ok_or_else(|| io::Error::other("monotonic overflow"))
}
pub fn wait(fd: i32, events: i16, end: u64) -> io::Result<()> {
    loop {
        let left = end.checked_sub(now()?).filter(|x| *x > 0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "original control end")
        })?;
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = left.div_ceil(1_000_000).min(i32::MAX as u64) as i32;
        let n = unsafe { libc::poll(&mut p, 1, millis) };
        if n > 0 {
            if p.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::other("invalid IPC fd"));
            }
            return Ok(());
        }
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
pub fn send(socket: &mut UnixStream, r: Record, end: u64) -> io::Result<()> {
    let b = r.encode();
    let mut pos = 0;
    while pos < BYTES {
        if now()? >= end {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "send end"));
        }
        match socket.write(&b[pos..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(socket.as_raw_fd(), libc::POLLOUT, end)?
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
pub fn receive(socket: &mut UnixStream, end: u64) -> io::Result<[u8; BYTES]> {
    let mut b = [0; BYTES];
    let mut pos = 0;
    while pos < BYTES {
        if now()? >= end {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "receive end"));
        }
        match socket.read(&mut b[pos..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(socket.as_raw_fd(), libc::POLLIN, end)?
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(b)
}
pub fn identity(fd: i32) -> io::Result<(u64, u64, u64, u32)> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut s) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        s.st_dev as u64,
        s.st_rdev as u64,
        s.st_ino,
        s.st_mode as u32,
    ))
}
