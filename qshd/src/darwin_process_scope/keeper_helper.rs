//! Inherited keeper endpoints and bounded bootstrap data. Helper roles enter
//! before the daemon creates a runtime; these are not public daemon commands.
use super::keeper::{encode, Decoder, Frame, ProtocolError};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

pub(super) const ENTRY: &str = "__qshd-keeper-v1";
const LAUNCH_MAGIC: &[u8; 8] = b"QSHKARG1";
const MAX_LAUNCH: usize = 6 * transport::channel::MAX_COMMAND_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Launch {
    pub argv: Vec<String>,
    pub environment: Vec<(String, String)>,
}
impl Launch {
    pub fn encode(&self, instance: [u8; 16]) -> Result<Vec<u8>, ProtocolError> {
        let total = self
            .argv
            .iter()
            .try_fold(0usize, |n, a| n.checked_add(a.len()));
        if self.argv.is_empty()
            || self.argv[0].is_empty()
            || self.argv.len() > transport::channel::MAX_COMMAND_LEN
            || total.is_none_or(|n| n > transport::channel::MAX_COMMAND_LEN)
            || self.argv.iter().any(|s| s.as_bytes().contains(&0))
        {
            return Err(ProtocolError);
        }
        let env_bytes = self.environment.iter().try_fold(0usize, |n, (k, v)| {
            n.checked_add(k.len())?.checked_add(v.len())
        });
        if self.environment.len() > 16
            || env_bytes.is_none_or(|n| n > transport::channel::MAX_COMMAND_LEN)
            || self.environment.iter().any(|(k, v)| {
                k.is_empty()
                    || k.contains('=')
                    || k.as_bytes().contains(&0)
                    || v.as_bytes().contains(&0)
            })
        {
            return Err(ProtocolError);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&instance);
        body.extend_from_slice(&(self.argv.len() as u32).to_be_bytes());
        for arg in &self.argv {
            body.extend_from_slice(&(arg.len() as u32).to_be_bytes());
            body.extend_from_slice(arg.as_bytes());
        }
        body.extend_from_slice(&(self.environment.len() as u32).to_be_bytes());
        for (key, value) in &self.environment {
            for text in [key, value] {
                body.extend_from_slice(&(text.len() as u32).to_be_bytes());
                body.extend_from_slice(text.as_bytes());
            }
        }
        if body.len() > MAX_LAUNCH {
            return Err(ProtocolError);
        }
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(LAUNCH_MAGIC);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
    pub fn decode(bytes: &[u8], instance: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes.len() < 32 || &bytes[..8] != LAUNCH_MAGIC {
            return Err(ProtocolError);
        }
        let len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if len > MAX_LAUNCH || bytes.len() != 12 + len || bytes[12..28] != instance {
            return Err(ProtocolError);
        }
        let count = u32::from_be_bytes(bytes[28..32].try_into().unwrap()) as usize;
        if count == 0 || count > transport::channel::MAX_COMMAND_LEN {
            return Err(ProtocolError);
        }
        let mut at = 32usize;
        let mut argv = Vec::new();
        for _ in 0..count {
            let end = at
                .checked_add(4)
                .filter(|end| *end <= bytes.len())
                .ok_or(ProtocolError)?;
            let len = u32::from_be_bytes(bytes[at..end].try_into().unwrap()) as usize;
            at = end;
            let end = at
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or(ProtocolError)?;
            let arg = std::str::from_utf8(&bytes[at..end]).map_err(|_| ProtocolError)?;
            argv.push(arg.to_owned());
            at = end;
        }
        let end = at
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or(ProtocolError)?;
        let count = u32::from_be_bytes(bytes[at..end].try_into().unwrap()) as usize;
        at = end;
        if count > 16 {
            return Err(ProtocolError);
        }
        let mut environment = Vec::new();
        for _ in 0..count {
            let mut pair = Vec::with_capacity(2);
            for _ in 0..2 {
                let end = at
                    .checked_add(4)
                    .filter(|end| *end <= bytes.len())
                    .ok_or(ProtocolError)?;
                let len = u32::from_be_bytes(bytes[at..end].try_into().unwrap()) as usize;
                at = end;
                let end = at
                    .checked_add(len)
                    .filter(|end| *end <= bytes.len())
                    .ok_or(ProtocolError)?;
                pair.push(
                    std::str::from_utf8(&bytes[at..end])
                        .map_err(|_| ProtocolError)?
                        .to_owned(),
                );
                at = end;
            }
            let value = pair.pop().ok_or(ProtocolError)?;
            let key = pair.pop().ok_or(ProtocolError)?;
            environment.push((key, value));
        }
        if at != bytes.len() {
            return Err(ProtocolError);
        }
        let launch = Self { argv, environment };
        // Enforce the same typed bounds in both directions, including NUL and
        // first-word rules. No executable or environment is consulted here.
        launch.encode(instance)?;
        Ok(launch)
    }
}

/// Holds one pending fixed record; partial writes cannot be replaced by another
/// message. EOF and malformed records never become drainage evidence.
pub(super) struct Channel {
    socket: UnixStream,
    decoder: Decoder,
    instance: [u8; 16],
    sequence: u64,
    pending: Option<([u8; 72], usize)>,
}
impl Channel {
    pub fn new(socket: UnixStream, instance: [u8; 16]) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            decoder: Decoder::new(instance),
            instance,
            sequence: 0,
            pending: None,
        })
    }
    #[cfg(all(test, target_os = "macos"))]
    pub fn shutdown(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
    pub fn queue(&mut self, frame: Frame) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.pending = Some((encode(self.instance, self.sequence, frame), 0));
        Ok(())
    }
    pub fn flush(&mut self) -> io::Result<bool> {
        let Some((bytes, at)) = &mut self.pending else {
            return Ok(true);
        };
        match self.socket.write(&bytes[*at..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => *at += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(false)
            }
            Err(error) => return Err(error),
        }
        if *at == bytes.len() {
            self.pending = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub fn bootstrap(&mut self, bytes: &[u8], at: &mut usize) -> io::Result<bool> {
        if self.sequence != 0
            || self.pending.is_some()
            || bytes.len() > MAX_LAUNCH + 12
            || *at > bytes.len()
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if *at == bytes.len() {
            return Ok(true);
        }
        match self.socket.write(&bytes[*at..]) {
            Ok(0) => Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                *at += n;
                Ok(*at == bytes.len())
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    pub fn receive(&mut self) -> io::Result<Option<Frame>> {
        let mut bytes = [0; 72];
        let limit = self.decoder.remaining();
        match self.socket.read(&mut bytes[..limit]) {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => self
                .decoder
                .feed(&bytes[..n])
                .map_err(|_| io::ErrorKind::InvalidData.into()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct EntryArgs {
    pub parent: i32,
    pub session_fd: i32,
    pub broker_fd: i32,
    pub instance: [u8; 16],
}
impl EntryArgs {
    pub fn parse(args: &[OsString]) -> Result<Self, ProtocolError> {
        if args.len() != 5 || args[0] != ENTRY {
            return Err(ProtocolError);
        }
        let integer = |arg: &OsString| {
            arg.to_str()
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|n| *n > 0)
                .ok_or(ProtocolError)
        };
        let parent = integer(&args[1])?;
        let session_fd = integer(&args[2])?;
        let broker_fd = integer(&args[3])?;
        if session_fd < 3 || broker_fd < 3 || session_fd == broker_fd {
            return Err(ProtocolError);
        }
        let text = args[4].to_str().ok_or(ProtocolError)?;
        if text.len() != 32
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProtocolError);
        }
        let mut instance = [0; 16];
        hex::decode_to_slice(text, &mut instance).map_err(|_| ProtocolError)?;
        Ok(Self {
            parent,
            session_fd,
            broker_fd,
            instance,
        })
    }
}

/// Application obligations are independent of the current session membership.
#[derive(Default)]
pub(super) struct ApplicationDebt {
    members: Vec<super::Identity>,
}
impl ApplicationDebt {
    /// `all` must be a new successful, unfiltered strong census. A filtered
    /// session view or failed inspection cannot provide positive exclusion.
    pub fn reconcile(
        &mut self,
        current: &[super::Classified],
        all: Result<&[super::Classified], super::Failure>,
    ) {
        let Ok(all) = all else { return };
        self.members.retain(|identity| {
            all.iter()
                .any(|p| p.identity.same_process(*identity) && p.class != super::Class::Zombie)
        });
        for process in current {
            if !self
                .members
                .iter()
                .any(|id| id.same_process(process.identity))
            {
                self.members.push(process.identity);
            }
        }
    }
    pub fn can_close(&self, application_waited: bool) -> bool {
        application_waited && self.members.is_empty()
    }
}

// Observation-only records; these never supply admission or signal authority.
#[cfg(any(test, all(target_os = "macos", feature = "test-darwin-keeper")))]
pub(super) fn fixture_debt_request(nonce: &str, bytes: &[u8]) -> Option<super::Identity> {
    if bytes.len() > 128
        || nonce.len() != 32
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let fields: Vec<_> = text.split(' ').collect();
    if fields.len() != 4 || fields[0] != nonce {
        return None;
    }
    let identity = super::Identity {
        pid: fields[1].parse().ok()?,
        unique: fields[2].parse().ok()?,
        version: fields[3].parse().ok()?,
    };
    if !identity.valid()
        || identity.version == 0
        || bytes
            != format!(
                "{nonce} {} {} {}\n",
                identity.pid, identity.unique, identity.version
            )
            .as_bytes()
    {
        return None;
    }
    Some(identity)
}
#[cfg(any(test, all(target_os = "macos", feature = "test-darwin-keeper")))]
fn fixture_debt_record(members: &[super::Identity], nonce: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    let requested = fixture_debt_request(nonce, bytes)?;
    // ApplicationDebt deliberately retains its first version across exec.
    // Emit that actual stored identity, never fabricate a refreshed version.
    let stored = members
        .iter()
        .find(|member| member.same_process(requested))?;
    Some(
        format!(
            "{nonce} {} {} {}\n",
            stored.pid, stored.unique, stored.version
        )
        .into_bytes(),
    )
}
#[cfg(test)]
mod fixture_debt_tests {
    use super::*;
    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    #[test]
    fn keeper_fixture_receipt_requires_actual_exact_ledger_insertion() {
        let identity = super::super::Identity {
            pid: 71,
            unique: 99,
            version: 3,
        };
        let record = b"0123456789abcdef0123456789abcdef 71 99 3\n";
        assert_eq!(fixture_debt_record(&[], NONCE, record), None);
        assert_eq!(
            fixture_debt_record(&[identity], NONCE, record),
            Some(record.to_vec())
        );
        for foreign in [
            super::super::Identity {
                pid: 72,
                ..identity
            },
            super::super::Identity {
                unique: 100,
                ..identity
            },
        ] {
            assert_eq!(
                fixture_debt_record(&[foreign], NONCE, record),
                None,
                "PID match alone must not open the escape gate"
            );
        }
        for malformed in [
            b"0123456789abcdef0123456789abcdef 071 99 3\n".as_slice(),
            b"0123456789abcdef0123456789abcdef 71 99 3",
            b"../ 71 99 3\n",
            b"0123456789abcdef0123456789abcdef 0 99 3\n",
            b"0123456789abcdef0123456789abcdef 71 99 0\n",
            b"ffffffffffffffffffffffffffffffff 71 99 3\n",
            b"0123456789abcdef0123456789abcdef 71 99 3\nextra",
        ] {
            assert_eq!(fixture_debt_record(&[identity], NONCE, malformed), None);
        }
    }
    #[test]
    fn keeper_fixture_exec_receipt_emits_stored_v0_for_real_same_process_v1() {
        let stored = super::super::Identity {
            pid: 71,
            unique: 99,
            version: 3,
        };
        let request = b"0123456789abcdef0123456789abcdef 71 99 4\n";
        assert_eq!(
            fixture_debt_request(NONCE, request),
            Some(super::super::Identity {
                version: 4,
                ..stored
            })
        );
        assert_eq!(
            fixture_debt_record(&[stored], NONCE, request),
            Some(b"0123456789abcdef0123456789abcdef 71 99 3\n".to_vec())
        );
    }
}

#[cfg(target_os = "macos")]
mod roles {
    use super::super::keeper::Operation;
    use super::*;
    use crate::darwin_process_scope::{native, Class, Identity, Ops};
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    const INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);
    /// Observe an actual ledger insertion; no wait or signal runs here. This
    /// entire path is absent from ordinary builds and only selected by a private
    /// fixture directory inherited by a compatibility-feature helper.
    #[cfg(feature = "test-darwin-keeper")]
    fn fixture_debt_observe(
        debt: &ApplicationDebt,
        snapshot: &[super::super::Classified],
    ) -> io::Result<()> {
        use std::io::{Read, Write};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let Some(path) = std::env::var_os("QSH_KEEPER_TEST_DEBT_DIRECTORY") else {
            return Ok(());
        };
        let path = std::path::PathBuf::from(path);
        if !path.is_absolute() {
            return Err(protocol());
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let meta = directory.metadata()?;
        if !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o700
        {
            return Err(protocol());
        }
        let read = |name: &[u8]| -> io::Result<Option<Vec<u8>>> {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr().cast(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let e = error();
                return if e.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != meta.uid()
                || m.mode() & 0o077 != 0
                || m.nlink() != 1
                || m.len() > 128
            {
                return Err(protocol());
            }
            let mut bytes = Vec::new();
            file.take(129).read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        };
        let Some(bytes) = read(b"target\0")? else {
            return Ok(());
        };
        let Some(nonce) = read(b"instance\0")? else {
            return Err(protocol());
        };
        let nonce = std::str::from_utf8(&nonce).map_err(|_| protocol())?;
        let Some(record) = fixture_debt_record(&debt.members, nonce, &bytes) else {
            return Ok(());
        };
        let publish = |name: &[u8]| -> io::Result<()> {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr().cast(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                if error().kind() == io::ErrorKind::AlreadyExists {
                    return if read(name)?.as_deref() == Some(record.as_slice()) {
                        Ok(())
                    } else {
                        Err(protocol())
                    };
                }
                return Err(error());
            }
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            file.write_all(&record)?;
            file.sync_all()
        };
        publish(b"ledger-recorded\0")?;
        let target = debt
            .members
            .iter()
            .find(|id| fixture_debt_record(&[**id], nonce, &bytes).is_some())
            .ok_or_else(protocol)?;
        let sid = unsafe { libc::getsid(0) };
        if snapshot.iter().any(|p| {
            p.identity.same_process(*target)
                && matches!(p.class,Class::Session(other) if other!=sid)
        }) {
            publish(b"foreign-observed\0")?;
        }
        Ok(())
    }
    fn error() -> io::Error {
        io::Error::last_os_error()
    }
    fn protocol() -> io::Error {
        io::ErrorKind::InvalidData.into()
    }
    fn native_error(_: crate::darwin_process_scope::Failure) -> io::Error {
        protocol()
    }
    fn connected(fd: RawFd) -> io::Result<()> {
        if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(protocol());
        }
        let mut kind = 0;
        let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut i32).cast(),
                &mut size,
            )
        } < 0
        {
            return Err(error());
        }
        if kind != libc::SOCK_STREAM || size as usize != std::mem::size_of_val(&kind) {
            return Err(protocol());
        }
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getpeername(
                fd,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(error());
        }
        if address.ss_family as i32 != libc::AF_UNIX {
            return Err(protocol());
        }
        Ok(())
    }
    fn close_except(keep: &[RawFd]) -> io::Result<()> {
        // This runs only in the early, single-threaded helper image or its
        // single-threaded forks. Finish enumeration before closing its own FD.
        let mut fds = Vec::new();
        for entry in std::fs::read_dir("/dev/fd")? {
            let entry = entry?;
            if let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<RawFd>().ok())
            {
                if !keep.contains(&fd) {
                    fds.push(fd);
                }
            }
            if fds.len() > 4096 {
                return Err(protocol());
            }
        }
        for fd in fds {
            if unsafe { libc::close(fd) } < 0 && error().raw_os_error() != Some(libc::EBADF) {
                return Err(error());
            }
        }
        Ok(())
    }
    fn helper_dispositions() -> io::Result<()> {
        for signal in [libc::SIGHUP, libc::SIGPIPE] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = libc::SIG_IGN;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } < 0
                || unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } < 0
            {
                return Err(error());
            }
        }
        Ok(())
    }
    fn send(channel: &mut Channel, frame: Frame) -> io::Result<()> {
        channel.queue(frame)?;
        while !channel.flush()? {
            std::thread::sleep(INTERVAL);
        }
        Ok(())
    }
    fn read_launch(stream: &mut UnixStream, instance: [u8; 16]) -> io::Result<Launch> {
        let mut header = [0; 12];
        stream.read_exact(&mut header)?;
        if &header[..8] != LAUNCH_MAGIC {
            return Err(protocol());
        }
        let count = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
        if count > MAX_LAUNCH {
            return Err(protocol());
        }
        let mut bytes = Vec::with_capacity(12 + count);
        bytes.extend_from_slice(&header);
        bytes.resize(12 + count, 0);
        stream.read_exact(&mut bytes[12..])?;
        Launch::decode(&bytes, instance).map_err(|_| protocol())
    }
    fn actual_wait(pid: i32) -> io::Result<i32> {
        use std::os::unix::process::ExitStatusExt;
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                return Ok(std::process::ExitStatus::from_raw(status)
                    .code()
                    .unwrap_or(1));
            }
            if result < 0 && error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error());
        }
    }
    pub(super) fn enter(args: EntryArgs) -> io::Result<()> {
        if unsafe { libc::getppid() } != args.parent {
            return Err(protocol());
        }
        connected(args.session_fd)?;
        connected(args.broker_fd)?;
        // Validation of both capabilities precedes ownership construction.
        let mut session = unsafe { UnixStream::from_raw_fd(args.session_fd) };
        let broker = unsafe { UnixStream::from_raw_fd(args.broker_fd) };
        close_except(&[0, 1, 2, session.as_raw_fd(), broker.as_raw_fd()])?;
        helper_dispositions()?;
        native::keeper_prepare().map_err(|_| protocol())?;
        let sid = unsafe { libc::getsid(0) };
        if sid <= 0 || sid != unsafe { libc::getpid() } || unsafe { libc::getpgrp() } != sid {
            return Err(protocol());
        }
        let launch = read_launch(&mut session, args.instance)?;
        let (s_side, b_side) = UnixStream::pair()?;
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(error());
        }
        if child == 0 {
            drop(session);
            drop(s_side);
            let code = match broker_main(broker, b_side, launch, args.instance, sid) {
                Ok(()) => 0,
                Err(_) => 125,
            };
            unsafe { libc::_exit(code) };
        }
        drop(broker);
        drop(b_side);
        let mut upstream = Channel::new(session, args.instance)?;
        let mut foreground = Channel::new(s_side, args.instance)?;
        send(
            &mut upstream,
            Frame {
                operation: super::super::keeper::Operation::Ready,
                fields: [sid as i64, child as i64, 0, 0],
            },
        )?;
        let mut slave_closed = false;
        let mut foreground_done = false;
        loop {
            if !foreground_done {
                if let Some(frame) = foreground.receive()? {
                    if frame.operation == Operation::AppNotStarted && frame.fields == [0; 4] {
                        // B has permanently frozen admission. Retain S's slave
                        // until the existing terminal-B/final-Exit handshake,
                        // without treating the later foreground EOF as loss.
                        foreground_done = true;
                    } else {
                        if frame.operation != Operation::Foreground || frame.fields[1..] != [0; 3] {
                            return Err(protocol());
                        }
                        let pid = i32::try_from(frame.fields[0]).map_err(|_| protocol())?;
                        // The authenticated B endpoint describes its gated,
                        // exclusively unreaped direct A child. Its PID cannot be
                        // reused here, and the trusted gate cannot exec or move
                        // until this reply. This is not a kernel signal token.
                        if pid <= 0
                            || unsafe { libc::getpgid(pid) } != pid
                            || unsafe { libc::getsid(pid) } != sid
                        {
                            return Err(protocol());
                        }
                        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
                        let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
                        ignore.sa_sigaction = libc::SIG_IGN;
                        if unsafe { libc::sigemptyset(&mut ignore.sa_mask) } < 0
                            || unsafe { libc::sigaction(libc::SIGTTOU, &ignore, &mut old) } < 0
                        {
                            return Err(error());
                        }
                        let result = unsafe { libc::tcsetpgrp(0, pid) };
                        let restore =
                            unsafe { libc::sigaction(libc::SIGTTOU, &old, std::ptr::null_mut()) };
                        if result < 0
                            || restore < 0
                            || unsafe { libc::getpgid(pid) } != pid
                            || unsafe { libc::getsid(pid) } != sid
                        {
                            return Err(error());
                        }
                        send(
                            &mut foreground,
                            Frame {
                                operation: Operation::ForegroundReady,
                                fields: frame.fields,
                            },
                        )?;
                        // B acknowledges actual A exec or an explicit owned startup failure.
                        loop {
                            match foreground.receive()? {
                                Some(ack)
                                    if matches!(
                                        ack.operation,
                                        Operation::AppStarted | Operation::AppFailed
                                    ) && ack.fields == frame.fields =>
                                {
                                    break
                                }
                                Some(_) => return Err(protocol()),
                                None => std::thread::sleep(INTERVAL),
                            }
                        }
                        for fd in 0..3 {
                            if unsafe { libc::close(fd) } < 0 {
                                return Err(error());
                            }
                        }
                        slave_closed = true;
                        foreground_done = true;
                    }
                }
            }
            if let Some(frame) = upstream.receive()? {
                if frame.operation != super::super::keeper::Operation::Exit
                    || frame.fields != [0; 4]
                {
                    return Err(protocol());
                }
                let mut ops = native::NativeOps;
                if ops
                    .keeper_child_status(child)
                    .map_err(native_error)?
                    .is_none()
                {
                    return Err(protocol());
                }
                actual_wait(child)?;
                if !slave_closed {
                    for fd in 0..3 {
                        unsafe { libc::close(fd) };
                    }
                }
                return Ok(());
            }
            std::thread::sleep(INTERVAL);
        }
    }
    // A positive fork result remains a distinct direct-child right until the
    // sole B wait consumes it. It is not a fabricated libproc identity/token.
    struct Application {
        pid: i32,
        wait: Option<i32>,
    }
    struct Keeper {
        pid: i32,
        requested: i32,
        control: Option<Channel>,
        claim: Option<(Identity, i32)>,
        notified: bool,
        waited: bool,
        failed_join: bool,
        needed: bool,
        destination_used: bool,
        terminal_sent: bool,
        hup_members: Vec<Identity>,
        kill_members: Vec<Identity>,
    }
    fn application_signals() -> io::Result<()> {
        let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut empty) } < 0
            || unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) } < 0
        {
            return Err(error());
        }
        for signal in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGALRM,
            libc::SIGPIPE,
            libc::SIGCHLD,
            libc::SIGTTIN,
            libc::SIGTTOU,
            libc::SIGTSTP,
        ] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = libc::SIG_DFL;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } < 0
                || unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } < 0
            {
                return Err(error());
            }
        }
        Ok(())
    }
    fn receive_blocking(channel: &mut Channel) -> io::Result<Frame> {
        loop {
            if let Some(frame) = channel.receive()? {
                return Ok(frame);
            }
            std::thread::sleep(INTERVAL);
        }
    }
    fn application_child(
        socket: UnixStream,
        launch: &Launch,
        instance: [u8; 16],
        sid: i32,
    ) -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        close_except(&[0, 1, 2, socket.as_raw_fd()])?;
        if unsafe { libc::setpgid(0, 0) } < 0 || unsafe { libc::getsid(0) } != sid {
            return Err(error());
        }
        let pid = unsafe { libc::getpid() };
        let mut gate = Channel::new(socket, instance)?;
        send(
            &mut gate,
            Frame {
                operation: Operation::Foreground,
                fields: [pid as i64, pid as i64, sid as i64, 0],
            },
        )?;
        let go = receive_blocking(&mut gate)?;
        if go.operation != Operation::Admit || go.fields != [0; 4] {
            return Err(protocol());
        }
        application_signals()?;
        let fd = gate.socket.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(error());
        }
        let _exec_error = std::process::Command::new(&launch.argv[0])
            .args(&launch.argv[1..])
            .envs(launch.environment.iter().map(|(k, v)| (k, v)))
            .exec();
        send(
            &mut gate,
            Frame {
                operation: Operation::Refused,
                fields: [127, 0, 0, 0],
            },
        )?;
        Err(protocol())
    }
    fn start_application(
        foreground: &mut Channel,
        launch: &Launch,
        instance: [u8; 16],
        sid: i32,
    ) -> io::Result<(Application, bool)> {
        let (parent, child) = UnixStream::pair()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(error());
        }
        if pid == 0 {
            drop(parent);
            let _ = application_child(child, launch, instance, sid);
            unsafe { libc::_exit(127) };
        }
        drop(child);
        let mut gate = Channel::new(parent, instance)?;
        let ready = receive_blocking(&mut gate)?;
        if ready.operation != Operation::Foreground
            || ready.fields != [pid as i64, pid as i64, sid as i64, 0]
        {
            return Err(protocol());
        }
        let request = Frame {
            operation: Operation::Foreground,
            fields: [pid as i64, 0, 0, 0],
        };
        send(foreground, request)?;
        let ack = receive_blocking(foreground)?;
        if ack.operation != Operation::ForegroundReady || ack.fields != request.fields {
            return Err(protocol());
        }
        send(
            &mut gate,
            Frame {
                operation: Operation::Admit,
                fields: [0; 4],
            },
        )?;
        let mut refused = false;
        loop {
            match gate.receive() {
                Ok(Some(frame))
                    if !refused
                        && frame.operation == Operation::Refused
                        && frame.fields == [127, 0, 0, 0] =>
                {
                    refused = true
                }
                Ok(Some(_)) => return Err(protocol()),
                Ok(None) => std::thread::sleep(INTERVAL),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        send(
            foreground,
            Frame {
                operation: if refused {
                    Operation::AppFailed
                } else {
                    Operation::AppStarted
                },
                fields: request.fields,
            },
        )?;
        for fd in 0..3 {
            if unsafe { libc::close(fd) } < 0 {
                return Err(error());
            }
        }
        Ok((Application { pid, wait: None }, refused))
    }
    fn keeper_child(
        socket: UnixStream,
        requested: i32,
        instance: [u8; 16],
        sid: i32,
    ) -> io::Result<()> {
        close_except(&[socket.as_raw_fd()])?;
        helper_dispositions()?;
        let mut control = Channel::new(socket, instance)?;
        if unsafe { libc::setpgid(0, requested) } < 0 {
            send(
                &mut control,
                Frame {
                    operation: Operation::Refused,
                    fields: [1, 0, 0, 0],
                },
            )?;
            return Err(protocol());
        }
        let group = unsafe { libc::getpgrp() };
        if group <= 0 || unsafe { libc::getsid(0) } != sid {
            return Err(protocol());
        }
        let mut ops = native::NativeOps;
        let pid = unsafe { libc::getpid() };
        let identity = loop {
            match ops.identity(pid) {
                Ok(identity) => break identity,
                Err(_) => {
                    match control.receive() {
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                        Err(e) => return Err(e),
                        Ok(Some(_)) => return Err(protocol()),
                        Ok(None) => {}
                    }
                    std::thread::sleep(INTERVAL);
                }
            }
        };
        send(
            &mut control,
            Frame {
                operation: Operation::KeeperReady,
                fields: [
                    group as i64,
                    sid as i64,
                    identity.unique as i64,
                    identity.version as i64,
                ],
            },
        )?;
        loop {
            match control.receive() {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
                Ok(Some(_)) => return Err(protocol()),
                Ok(None) => std::thread::sleep(INTERVAL),
            }
        }
    }
    fn create_keeper(requested: i32, instance: [u8; 16], sid: i32) -> io::Result<Keeper> {
        let (parent, child) = UnixStream::pair()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(error());
        }
        if pid == 0 {
            drop(parent);
            let code = if keeper_child(child, requested, instance, sid).is_ok() {
                0
            } else {
                125
            };
            unsafe { libc::_exit(code) };
        }
        drop(child);
        Ok(Keeper {
            pid,
            requested,
            control: Some(Channel::new(parent, instance)?),
            claim: None,
            notified: false,
            waited: false,
            failed_join: false,
            needed: true,
            destination_used: false,
            terminal_sent: false,
            hup_members: Vec::new(),
            kill_members: Vec::new(),
        })
    }
    fn refresh_keeper(k: &mut Keeper, upstream: &mut Channel, sid: i32) -> io::Result<()> {
        if k.waited {
            return Ok(());
        }
        let mut ops = native::NativeOps;
        let terminal = ops.keeper_child_status(k.pid).map_err(native_error)?;
        if k.claim.is_none() && !k.failed_join && k.control.is_some() {
            match k.control.as_mut().ok_or_else(protocol)?.receive() {
                Ok(Some(frame)) if frame.operation == Operation::KeeperReady => {
                    let group = i32::try_from(frame.fields[0]).map_err(|_| protocol())?;
                    let version = u32::try_from(frame.fields[3]).map_err(|_| protocol())?;
                    if group <= 0
                        || frame.fields[1] != sid as i64
                        || (k.requested != 0 && group != k.requested)
                    {
                        return Err(protocol());
                    }
                    k.claim = Some((
                        Identity {
                            pid: k.pid,
                            unique: frame.fields[2] as u64,
                            version,
                        },
                        group,
                    ));
                }
                Ok(Some(frame))
                    if frame.operation == Operation::Refused && frame.fields == [1, 0, 0, 0] =>
                {
                    k.failed_join = true
                }
                Ok(Some(_)) => return Err(protocol()),
                Ok(None) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && terminal.is_some() => {
                    k.failed_join = true
                }
                Err(e) => return Err(e),
            }
        }
        if let Some((expected, group)) = k.claim {
            if !k.notified {
                let current = match ops.identity(k.pid) {
                    Ok(current) => current,
                    Err(_) => return Ok(()),
                };
                if current != expected {
                    return Err(protocol());
                }
                let class = match ops.classify(k.pid) {
                    Ok(value) => value.class,
                    Err(_) => return Ok(()),
                };
                if class != Class::Zombie {
                    if class != Class::Session(sid) {
                        return Err(protocol());
                    }
                    match ops.keeper_group(expected, sid) {
                        Ok(actual) if actual == group => {}
                        Ok(_) => return Err(protocol()),
                        Err(_) => return Ok(()),
                    }
                }
                send(
                    upstream,
                    Frame {
                        operation: Operation::KeeperCreated,
                        fields: [
                            k.pid as i64,
                            expected.unique as i64,
                            expected.version as i64,
                            group as i64,
                        ],
                    },
                )?;
                k.notified = true;
            }
        }
        if let Some(code) = terminal {
            if !k.terminal_sent {
                send(
                    upstream,
                    Frame {
                        operation: Operation::KeeperTerminal,
                        fields: [k.pid as i64, code as i64, 0, 0],
                    },
                )?;
                k.terminal_sent = true;
            }
        }
        if k.failed_join && terminal.is_some() {
            // No pin was ever admitted; its failed child can be consumed without
            // discharging any application debt or in-flight group operation.
            let code = actual_wait(k.pid)?;
            if terminal != Some(code) {
                return Err(protocol());
            }
            k.waited = true;
            k.needed = false;
            k.control.take();
            send(
                upstream,
                Frame {
                    operation: Operation::KeeperWait,
                    fields: [k.pid as i64, code as i64, 0, 0],
                },
            )?;
        }
        Ok(())
    }
    fn valid_pin(k: &Keeper, group: i32, sid: i32) -> bool {
        if !k.needed || k.waited || !k.notified {
            return false;
        }
        let Some((identity, actual)) = k.claim else {
            return false;
        };
        if actual != group {
            return false;
        }
        let mut ops = native::NativeOps;
        let Ok(terminal) = ops.keeper_child_status(k.pid) else {
            return false;
        };
        let Ok(current) = ops.identity(k.pid) else {
            return false;
        };
        if current != identity {
            return false;
        }
        if terminal.is_some() {
            return true;
        }
        ops.keeper_group(identity, sid) == Ok(group)
    }
    fn ensure_pin(
        keepers: &mut Vec<Keeper>,
        group: i32,
        upstream: &mut Channel,
        instance: [u8; 16],
        sid: i32,
    ) -> io::Result<bool> {
        if keepers.iter().any(|k| valid_pin(k, group, sid)) {
            return Ok(true);
        }
        if keepers.iter().any(|k| {
            !k.waited && (k.requested == group || k.claim.is_some_and(|(_, g)| g == group))
        }) || keepers.len() >= 8
        {
            return Ok(false);
        }
        let keeper = create_keeper(group, instance, sid)?;
        send(
            upstream,
            Frame {
                operation: Operation::KeeperSpawned,
                fields: [keeper.pid as i64, 0, 0, 0],
            },
        )?;
        keepers.push(keeper);
        Ok(false)
    }
    fn broker_main(
        socket: UnixStream,
        foreground: UnixStream,
        launch: Launch,
        instance: [u8; 16],
        sid: i32,
    ) -> io::Result<()> {
        close_except(&[0, 1, 2, socket.as_raw_fd(), foreground.as_raw_fd()])?;
        if unsafe { libc::setpgid(0, 0) } < 0 || unsafe { libc::getsid(0) } != sid {
            return Err(error());
        }
        helper_dispositions()?;
        let me = unsafe { libc::getpid() };
        let mut ops = native::NativeOps;
        let own = ops.identity(me).map_err(native_error)?;
        let reservation = ops.identity(sid).map_err(native_error)?;
        let mut upstream = Channel::new(socket, instance)?;
        let mut foreground = Channel::new(foreground, instance)?;
        send(
            &mut upstream,
            Frame {
                operation: Operation::Ready,
                fields: [me as i64, unsafe { libc::getpgrp() } as i64, sid as i64, 0],
            },
        )?;
        let mut parent_reported = unsafe { libc::getppid() };
        let mut app: Option<Application> = None;
        let mut decision = super::super::keeper::AdmissionDecision::Pending;
        let mut phase = None;
        let mut keepers = Vec::new();
        let mut application_debt = ApplicationDebt::default();
        let mut closing = false;
        let mut drained = false;
        loop {
            let parent = unsafe { libc::getppid() };
            if parent != parent_reported {
                send(
                    &mut upstream,
                    Frame {
                        operation: Operation::BrokerParent,
                        fields: [me as i64, parent as i64, sid as i64, 0],
                    },
                )?;
                parent_reported = parent;
            }
            if let Some(frame) = upstream.receive()? {
                match frame.operation {
                    Operation::Admit
                        if decision == super::super::keeper::AdmissionDecision::Pending
                            && app.is_none()
                            && phase.is_none()
                            && !closing
                            && frame.fields == [0; 4] =>
                    {
                        decision
                            .commit(super::super::keeper::AdmissionDecision::Admit)
                            .map_err(|_| protocol())?;
                        let (created, refused) =
                            start_application(&mut foreground, &launch, instance, sid)?;
                        send(
                            &mut upstream,
                            Frame {
                                operation: if refused {
                                    Operation::AppFailed
                                } else {
                                    Operation::AppStarted
                                },
                                fields: [
                                    created.pid as i64,
                                    0,
                                    0,
                                    if refused { 127 } else { sid as i64 },
                                ],
                            },
                        )?;
                        app = Some(created);
                    }
                    Operation::AbortBeforeAdmit
                        if decision == super::super::keeper::AdmissionDecision::Pending
                            && app.is_none()
                            && phase.is_none()
                            && !closing
                            && frame.fields == [0; 4] =>
                    {
                        decision
                            .commit(super::super::keeper::AdmissionDecision::Abort)
                            .map_err(|_| protocol())?;
                        // B's unused slave copies are no longer needed. S retains
                        // its own slave until the existing final Exit handshake.
                        for fd in [0, 1, 2] {
                            if unsafe { libc::close(fd) } < 0 {
                                return Err(error());
                            }
                        }
                        send(
                            &mut foreground,
                            Frame {
                                operation: Operation::AppNotStarted,
                                fields: [0; 4],
                            },
                        )?;
                        send(
                            &mut upstream,
                            Frame {
                                operation: Operation::AppNotStarted,
                                fields: [0; 4],
                            },
                        )?;
                    }
                    Operation::Stop
                        if frame.fields[1..] == [0; 3] && matches!(frame.fields[0], 1 | 9) =>
                    {
                        if !closing {
                            let requested = frame.fields[0] as i32;
                            phase = Some(if phase == Some(libc::SIGKILL) {
                                libc::SIGKILL
                            } else {
                                requested
                            });
                        }
                    }
                    Operation::Exit if drained && frame.fields == [0; 4] => return Ok(()),
                    _ => return Err(protocol()),
                }
            }
            for keeper in &mut keepers {
                refresh_keeper(keeper, &mut upstream, sid)?;
            }
            if let Some(application) = &mut app {
                if application.wait.is_none() {
                    if let Some(observed) = ops
                        .keeper_child_status(application.pid)
                        .map_err(native_error)?
                    {
                        let actual = actual_wait(application.pid)?;
                        if actual != observed {
                            return Err(protocol());
                        }
                        application.wait = Some(actual);
                        send(
                            &mut upstream,
                            Frame {
                                operation: Operation::AppWait,
                                fields: [application.pid as i64, actual as i64, 0, 0],
                            },
                        )?;
                    }
                }
            }
            if !closing {
                let snapshot = match ops.keeper_full_census() {
                    Ok(value) => value,
                    Err(error) => {
                        application_debt.reconcile(&[], Err(error));
                        std::thread::sleep(INTERVAL);
                        continue;
                    }
                };
                let application_members: Vec<_> = snapshot
                    .iter()
                    .copied()
                    .filter(|p| {
                        p.class == Class::Session(sid)
                            && p.identity != own
                            && p.identity != reservation
                            && !keepers.iter().any(|k| !k.waited && k.pid == p.identity.pid)
                    })
                    .collect();
                application_debt.reconcile(&application_members, Ok(&snapshot));
                #[cfg(feature = "test-darwin-keeper")]
                fixture_debt_observe(&application_debt, &snapshot)?;
                if application_debt.can_close(
                    decision == super::super::keeper::AdmissionDecision::Abort
                        || app.as_ref().is_some_and(|a| a.wait.is_some()),
                ) {
                    // No uncontrolled member can fork now; only B could create
                    // another keeper, and its admission is closed first.
                    closing = true;
                    for k in &mut keepers {
                        k.needed = false;
                        k.control.take();
                    }
                } else if let Some(signal) = phase {
                    let mut groups = Vec::new();
                    let mut memberships = Vec::new();
                    let mut complete = true;
                    for process in &application_members {
                        match ops.keeper_group(process.identity, sid) {
                            Ok(group) => {
                                if !groups.contains(&group) {
                                    groups.push(group);
                                }
                                memberships.push((group, process.identity));
                            }
                            Err(_) => complete = false,
                        }
                    }
                    if complete {
                        let current = unsafe { libc::getpgrp() };
                        if groups.contains(&current) {
                            if ensure_pin(&mut keepers, current, &mut upstream, instance, sid)? {
                                if !keepers
                                    .iter()
                                    .any(|k| !k.waited && k.requested == 0 && !k.destination_used)
                                    && keepers.len() < 8
                                {
                                    let keeper = create_keeper(0, instance, sid)?;
                                    send(
                                        &mut upstream,
                                        Frame {
                                            operation: Operation::KeeperSpawned,
                                            fields: [keeper.pid as i64, 0, 0, 0],
                                        },
                                    )?;
                                    keepers.push(keeper);
                                }
                                if !keepers.iter().any(|k| !k.waited && !k.notified) {
                                    if let Some(destination) = keepers
                                        .iter()
                                        .filter(|k| k.requested == 0 && !k.destination_used)
                                        .filter_map(|k| k.claim.map(|(_, g)| g))
                                        .find(|g| {
                                            *g != current
                                                && keepers.iter().any(|k| valid_pin(k, *g, sid))
                                        })
                                    {
                                        if !keepers.iter().any(|k| valid_pin(k, current, sid)) {
                                            return Err(protocol());
                                        }
                                        if unsafe { libc::setpgid(0, destination) } < 0 {
                                            std::thread::sleep(INTERVAL);
                                            continue;
                                        }
                                        if unsafe { libc::getpgrp() } != destination
                                            || unsafe { libc::getsid(0) } != sid
                                        {
                                            return Err(protocol());
                                        }
                                        if let Some(k) = keepers.iter_mut().find(|k| {
                                            k.requested == 0
                                                && !k.destination_used
                                                && k.claim.is_some_and(|(_, g)| g == destination)
                                        }) {
                                            k.destination_used = true;
                                        }
                                        send(
                                            &mut upstream,
                                            Frame {
                                                operation: Operation::BrokerMoved,
                                                fields: [
                                                    me as i64,
                                                    destination as i64,
                                                    sid as i64,
                                                    0,
                                                ],
                                            },
                                        )?;
                                    }
                                }
                            }
                        }
                        for group in groups {
                            if group == unsafe { libc::getpgrp() } {
                                continue;
                            }
                            if ensure_pin(&mut keepers, group, &mut upstream, instance, sid)? {
                                // One synchronous loop serializes relocation and
                                // delivery. Membership is checked at delivery,
                                // not cached when the stop request was received.
                                if group == unsafe { libc::getpgrp() } {
                                    return Err(protocol());
                                }
                                let pin = keepers
                                    .iter_mut()
                                    .find(|k| {
                                        k.needed
                                            && !k.waited
                                            && k.notified
                                            && k.claim.is_some_and(|(_, g)| g == group)
                                    })
                                    .ok_or_else(protocol)?;
                                let seen = if signal == libc::SIGKILL {
                                    &mut pin.kill_members
                                } else {
                                    &mut pin.hup_members
                                };
                                let newly_observed: Vec<_> = memberships
                                    .iter()
                                    .filter_map(|(g, id)| {
                                        (*g == group && !seen.contains(id)).then_some(*id)
                                    })
                                    .collect();
                                if signal != libc::SIGKILL && newly_observed.is_empty() {
                                    continue;
                                }
                                if signal != libc::SIGKILL
                                    && seen
                                        .len()
                                        .checked_add(newly_observed.len())
                                        .is_none_or(|n| n > crate::darwin_process_scope::CAPACITY)
                                {
                                    continue;
                                }
                                if unsafe { libc::kill(-group, signal) } < 0 {
                                    continue;
                                }
                                if signal != libc::SIGKILL {
                                    seen.extend(newly_observed);
                                }
                            }
                        }
                    }
                }
            } else if !drained {
                for keeper in &mut keepers {
                    if !keeper.waited
                        && ops
                            .keeper_child_status(keeper.pid)
                            .map_err(native_error)?
                            .is_some()
                    {
                        let observed = ops
                            .keeper_child_status(keeper.pid)
                            .map_err(native_error)?
                            .ok_or_else(protocol)?;
                        if !keeper.terminal_sent {
                            send(
                                &mut upstream,
                                Frame {
                                    operation: Operation::KeeperTerminal,
                                    fields: [keeper.pid as i64, observed as i64, 0, 0],
                                },
                            )?;
                            keeper.terminal_sent = true;
                        }
                        let code = actual_wait(keeper.pid)?;
                        if code != observed {
                            return Err(protocol());
                        }
                        keeper.waited = true;
                        send(
                            &mut upstream,
                            Frame {
                                operation: Operation::KeeperWait,
                                fields: [keeper.pid as i64, code as i64, 0, 0],
                            },
                        )?;
                    }
                }
                if keepers.iter().all(|k| k.waited)
                    && (decision == super::super::keeper::AdmissionDecision::Abort
                        || app.as_ref().is_some_and(|a| a.wait.is_some()))
                {
                    send(
                        &mut upstream,
                        Frame {
                            operation: Operation::Drained,
                            fields: [keepers.len() as i64, 0, 0, 0],
                        },
                    )?;
                    drained = true;
                }
            }
            std::thread::sleep(INTERVAL);
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn entry(args: &[OsString]) -> Option<io::Result<()>> {
    if args.first().is_none_or(|arg| arg != ENTRY) {
        return None;
    }
    Some(
        EntryArgs::parse(args)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid keeper bootstrap"))
            .and_then(roles::enter),
    )
}
