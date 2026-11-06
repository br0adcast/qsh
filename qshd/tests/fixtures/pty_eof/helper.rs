// Standalone PTY control fixture for the dedicated diagnostic route.
// No libtest, Tokio, fork, threads, shell, process spawn, or grandchildren.
mod ipc;
#[allow(dead_code)] // Controller-only transcript gate shares the exact controller wire source.
mod wire;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::{env, io};
use wire::{MAX_INVENTORY, Op, Receiver, Record};
fn syscall(n: i32) -> io::Result<()> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
struct Helper {
    socket: UnixStream,
    nonce: [u8; 16],
    arm: u8,
    sequence: u32,
    end: u64,
}
impl Helper {
    fn emit(
        &mut self,
        op: Op,
        fd: i32,
        actual: io::Result<()>,
        identity: Option<(u64, u64, u64, u32)>,
    ) -> io::Result<()> {
        let mut r = Record::new(self.nonce, self.arm, self.sequence, op);
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("sequence overflow"))?;
        r.fd = fd;
        r.errno = actual
            .as_ref()
            .err()
            .and_then(|e| e.raw_os_error())
            .unwrap_or(if actual.is_ok() { 0 } else { -1 });
        if let Some((dev, rdev, ino, mode)) = identity {
            r.dev = dev;
            r.rdev = rdev;
            r.ino = ino;
            r.mode = mode;
        }
        r.pid = unsafe { libc::getpid() };
        r.sid = unsafe { libc::getsid(0) };
        r.group = unsafe { libc::getpgrp() };
        ipc::send(&mut self.socket, r, self.end)?;
        actual
    }
    fn close(&mut self, fd: i32, op: Op) -> io::Result<()> {
        let id = ipc::identity(fd)?;
        let result = if unsafe { libc::close(fd) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        };
        // EINTR is not retried on a descriptor number whose ownership may have changed.
        self.emit(op, fd, result, Some(id))
    }
    fn inventory(&mut self, slave: i32, alias: Option<i32>, initial: bool) -> io::Result<()> {
        let dir = unsafe { libc::opendir(c"/dev/fd".as_ptr()) };
        if dir.is_null() {
            return Err(io::Error::last_os_error());
        }
        let enumeration = unsafe { libc::dirfd(dir) };
        let mut found = Vec::new();
        let mut error = None;
        loop {
            if ipc::now()? >= self.end {
                error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "inventory work end",
                ));
                break;
            }
            unsafe {
                *libc::__error() = 0;
            }
            let e = unsafe { libc::readdir(dir) };
            if e.is_null() {
                let n = unsafe { *libc::__error() };
                if n != 0 {
                    error = Some(io::Error::from_raw_os_error(n));
                }
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*e).d_name.as_ptr()) };
            if let Ok(n) = name.to_string_lossy().parse::<i32>() {
                if n != enumeration {
                    match ipc::identity(n) {
                        Ok(id) => found.push((n, id)),
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
            }
            if found.len() > MAX_INVENTORY {
                error = Some(io::Error::other("own FD ceiling"));
                break;
            }
        }
        // The actual enumeration descriptor is positively known; close before IPC publication.
        let enumeration_identity = ipc::identity(enumeration);
        let close = if unsafe { libc::closedir(dir) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        };
        self.emit(
            Op::EnumerationClosed,
            enumeration,
            close,
            enumeration_identity.as_ref().ok().copied(),
        )?;
        enumeration_identity?;
        if let Some(e) = error {
            return Err(e);
        }
        found.sort_by_key(|x| x.0);
        for (fd, id) in found {
            self.emit(Op::Inventory, fd, Ok(()), Some(id))?;
            let intended = fd == self.socket.as_raw_fd() || fd == slave || Some(fd) == alias;
            if !intended {
                if !initial {
                    return Err(io::Error::other("unexpected post-close descriptor"));
                }
                self.close(fd, Op::ClosedAlias)?;
            }
        }
        self.emit(Op::InventoryEnd, enumeration, Ok(()), None)
    }
    fn run(&mut self, slave: i32) -> io::Result<()> {
        let id = ipc::identity(slave)?;
        if id.3 & libc::S_IFMT as u32 != libc::S_IFCHR as u32 {
            return Err(io::Error::other("slave is not character device"));
        }
        self.inventory(slave, None, true)?;
        // All arms start a new session; arm1 deliberately never associates a tty.
        let session = syscall(unsafe { libc::setsid() });
        self.emit(Op::Session, slave, session, Some(id))?;
        if self.arm >= 2 {
            let control = syscall(unsafe { libc::ioctl(slave, libc::TIOCSCTTY, 0) });
            self.emit(Op::Controlling, slave, control, Some(id))?;
            let foreground = syscall(unsafe { libc::tcsetpgrp(slave, libc::getpgrp()) });
            self.emit(Op::Foreground, slave, foreground, Some(id))?;
        }
        if self.arm == 3 {
            let fd = unsafe {
                libc::open(
                    c"/dev/tty".as_ptr(),
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                let e = io::Error::last_os_error();
                return self.emit(Op::CttyOpened, fd, Err(e), None);
            }
            let actual = ipc::identity(fd)?;
            self.emit(Op::CttyOpened, fd, Ok(()), Some(actual))?;
            self.close(fd, Op::CttyClosed)?;
        }
        let mut alias = None;
        if self.arm == 4 {
            let fd = unsafe { libc::fcntl(slave, libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                let e = io::Error::last_os_error();
                return self.emit(Op::AliasOpened, fd, Err(e), None);
            }
            self.emit(Op::AliasOpened, fd, Ok(()), Some(ipc::identity(fd)?))?;
            alias = Some(fd);
        }
        self.emit(Op::Ready, slave, Ok(()), Some(id))?;
        let mut rx = Receiver::new(self.nonce, self.arm);
        let mut slave_open = true;
        loop {
            let b = ipc::receive(&mut self.socket, self.end)?;
            let r = rx.accept(&b).map_err(io::Error::other)?;
            match r.op {
                Op::CloseSlave => {
                    if !slave_open {
                        return Err(io::Error::other("slave already closed"));
                    }
                    self.close(slave, Op::ClosedSlave)?;
                    slave_open = false;
                    self.inventory(-1, alias, false)?;
                }
                Op::CloseAlias => {
                    if slave_open {
                        return Err(io::Error::other("close slave first"));
                    }
                    let fd = alias.take().ok_or_else(|| io::Error::other("no alias"))?;
                    self.close(fd, Op::ClosedAlias)?;
                    self.inventory(-1, None, false)?;
                }
                Op::Release => {
                    if let Some(fd) = alias.take() {
                        self.close(fd, Op::ClosedAlias)?;
                    }
                    self.emit(Op::Released, -1, Ok(()), None)?;
                    return Ok(());
                }
                _ => return Err(io::Error::other("wrong controller operation")),
            }
        }
    }
}
fn main() -> std::process::ExitCode {
    // Fixed positional contract from the reviewed controller, no ambient selector.
    let args: Vec<_> = env::args().collect();
    if args.len() != 6 {
        return std::process::ExitCode::from(125);
    }
    let parsed = (|| -> Option<(i32, i32, u8, u64, [u8; 16])> {
        let ctl = args[1].parse().ok()?;
        let slave = args[2].parse().ok()?;
        let arm = args[3].parse().ok()?;
        let end = args[4].parse().ok()?;
        let hex = args[5].as_bytes();
        if hex.len() != 32 {
            return None;
        }
        let mut nonce = [0; 16];
        for i in 0..16 {
            nonce[i] =
                u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).ok()?, 16).ok()?;
        }
        Some((ctl, slave, arm, end, nonce))
    })();
    let Some((ctl, slave, arm, end, nonce)) = parsed else {
        return std::process::ExitCode::from(125);
    };
    if ctl < 3 || slave < 3 || ctl == slave || !(1..=4).contains(&arm) {
        return std::process::ExitCode::from(125);
    }
    let socket = unsafe { UnixStream::from_raw_fd(ctl) };
    if socket.set_nonblocking(true).is_err() {
        return std::process::ExitCode::from(125);
    }
    let mut helper = Helper {
        socket,
        nonce,
        arm,
        sequence: 0,
        end,
    };
    if let Err(e) = helper.run(slave) {
        let _ = helper.emit(Op::Refused, slave, Err(e), None);
        return std::process::ExitCode::from(125);
    }
    std::process::ExitCode::SUCCESS
}
