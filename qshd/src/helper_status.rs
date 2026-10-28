//! Root-only, local helper diagnostics. Snapshots never advance cleanup custody.
use serde::{Deserialize, Serialize};

pub const MAX_RESPONSE: usize = 4096;
pub const SCHEMA: u8 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u8,
    pub phase: Phase,
    pub capacity: Capacity,
    pub limit: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<Counts>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Serving,
    Stopping,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capacity {
    Available,
    Unavailable,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub admitted: u16,
    pub provisional: u16,
    pub retiring: u16,
    pub retiring_pending: u16,
    pub charged: u16,
    pub unconfirmed: u16,
    pub missing_monitor: u16,
    pub wait_lost: u16,
    pub monitor_failed: u16,
    pub receipt_lost: u16,
    pub retired_slots: u16,
    pub wait_outstanding: u16,
    pub receipt_outstanding: u16,
    pub pam: Pam,
    pub cleanup_failure: Option<CleanupFailure>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CleanupFailure {
    PtyLabelRestore { errno: i32 },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Pam {
    NotOpened,
    Finished {
        close_session: PamStep,
        delete_cred: PamStep,
        end: PamStep,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PamStep {
    Skipped,
    Ok,
    Failed,
}

#[cfg(all(target_os = "linux", feature = "system"))]
pub(crate) struct Endpoint {
    listener: std::os::unix::net::UnixListener,
    _cleanup: crate::control::SocketCleanup,
    lock: crate::control::EnsureLock,
    uid: u32,
    disabled: bool,
}
#[cfg(all(target_os = "linux", feature = "system"))]
impl Endpoint {
    pub(crate) fn bind(path: &std::path::Path) -> std::io::Result<Self> {
        if nix::unistd::geteuid().as_raw() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "helper status requires root",
            ));
        }
        Self::bind_for(path, 0)
    }
    pub(crate) fn bind_for(path: &std::path::Path, uid: u32) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "helper status socket must be absolute",
            ));
        }
        // Resolve without creation before EnsureLock's existing creation path.
        let (parent, _) = crate::host_key::trusted_parent(path, false)?;
        let m = parent.metadata()?;
        if m.uid() != uid || m.mode() & 0o7777 != 0o700 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "helper status requires an existing private directory owned by root",
            ));
        }
        let lock = crate::control::EnsureLock::acquire(path, std::time::Duration::ZERO)?;
        lock.require_private_parent(uid)?;
        // A cooperating live helper holds this lock for its entire lifetime.
        // Refuse other live listeners too; replace only an actually stale socket.
        if lock.endpoint_exists()? {
            match connect_until(path, std::time::Instant::now()) {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "helper status endpoint is live or unavailable",
                    ))
                }
            }
        }
        let (listener, cleanup) = lock.bind_private_owned()?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            _cleanup: cleanup,
            lock,
            uid,
            disabled: false,
        })
    }
    pub(crate) fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        (!self.disabled).then(|| self.listener.as_fd())
    }
    pub(crate) fn disable(&mut self) {
        self.disabled = true;
    }
    /// One accept and one send. A query never owns a helper-loop obligation.
    pub(crate) fn service(&mut self, snapshot: impl FnOnce() -> Vec<u8>) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        if self.disabled {
            return Ok(());
        }
        self.lock.require_private_parent(self.uid)?;
        let (client, _) = match self.listener.accept() {
            Ok(client) => client,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        let bytes = snapshot();
        // All errors below belong only to this disposable client.
        if bytes.len() > MAX_RESPONSE
            || client.set_nonblocking(true).is_err()
            || crate::control::peer_uid(&client).ok() != Some(self.uid)
        {
            return Ok(());
        }
        // SAFETY: client owns the socket; bytes is valid for its exact length.
        let _ = unsafe {
            nix::libc::send(
                client.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                nix::libc::MSG_DONTWAIT | nix::libc::MSG_NOSIGNAL,
            )
        };
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn connect_until(
    path: &std::path::Path,
    deadline: std::time::Instant,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    match connect(fd.as_raw_fd(), &UnixAddr::new(path)?) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => {
            wait_fd(fd.as_raw_fd(), nix::libc::POLLOUT, deadline)?;
            let stream: std::os::unix::net::UnixStream = fd.into();
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
            return Ok(stream);
        }
        Err(e) => return Err(e.into()),
    }
    Ok(fd.into())
}
#[cfg(target_os = "linux")]
fn wait_fd(
    fd: std::os::fd::RawFd,
    flags: i16,
    deadline: std::time::Instant,
) -> std::io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let mut p = nix::libc::pollfd {
            fd,
            events: flags,
            revents: 0,
        };
        let ms = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        // SAFETY: caller retains fd; p is one initialized poll descriptor.
        let result = unsafe { nix::libc::poll(&mut p, 1, ms) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// One operation budget covers nonblocking connect, peer validation and capped EOF.
#[cfg(target_os = "linux")]
pub fn query(path: &std::path::Path) -> anyhow::Result<Snapshot> {
    anyhow::ensure!(
        nix::unistd::geteuid().as_raw() == 0,
        "helper-status requires root"
    );
    query_for(path, 0)
}
#[cfg(target_os = "linux")]
fn query_for(path: &std::path::Path, uid: u32) -> anyhow::Result<Snapshot> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(path.is_absolute(), "helper status socket must be absolute");
    let deadline = std::time::Instant::now() + crate::control::CLIENT_READ_TIMEOUT;
    let (parent, _) = crate::host_key::trusted_parent(path, false)?;
    let authority = parent.metadata()?;
    anyhow::ensure!(
        authority.uid() == uid && authority.mode() & 0o7777 == 0o700,
        "helper status parent must be root-owned 0700"
    );
    let mut stream = connect_until(path, deadline)?;
    crate::control::require_same_account(crate::control::peer_uid(&stream), uid)?;
    let validate = || -> anyhow::Result<()> {
        let (now, _) = crate::host_key::trusted_parent(path, false)?;
        let m = now.metadata()?;
        anyhow::ensure!(
            m.dev() == authority.dev()
                && m.ino() == authority.ino()
                && m.uid() == uid
                && m.mode() & 0o7777 == 0o700,
            "helper status parent changed"
        );
        Ok(())
    };
    validate()?;
    let mut bytes = Vec::with_capacity(MAX_RESPONSE + 1);
    let mut buffer = [0u8; MAX_RESPONSE + 1];
    loop {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "helper status query timed out"
        );
        match stream.read(&mut buffer[..MAX_RESPONSE + 1 - bytes.len()]) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                anyhow::ensure!(
                    bytes.len() <= MAX_RESPONSE,
                    "helper status response exceeds cap"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait_fd(stream.as_raw_fd(), nix::libc::POLLIN, deadline)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    validate()?;
    anyhow::ensure!(
        std::time::Instant::now() < deadline,
        "helper status query timed out"
    );
    decode(&bytes)
}
#[cfg(not(target_os = "linux"))]
pub fn query(_path: &std::path::Path) -> anyhow::Result<Snapshot> {
    anyhow::bail!("helper-status is supported only on Linux")
}
#[cfg(target_os = "linux")]
fn decode(bytes: &[u8]) -> anyhow::Result<Snapshot> {
    anyhow::ensure!(
        bytes.len() <= MAX_RESPONSE,
        "helper status response exceeds cap"
    );
    let snapshot: Snapshot = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        snapshot.schema == SCHEMA,
        "unsupported helper status schema"
    );
    anyhow::ensure!(
        matches!(
            (&snapshot.capacity, &snapshot.counts),
            (Capacity::Available, Some(_)) | (Capacity::Unavailable, None)
        ),
        "inconsistent helper status availability"
    );
    Ok(snapshot)
}
/// Parse only the explicit local endpoint; never derive it from environment.
pub fn run_command(args: &[std::ffi::OsString]) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.len() == 3 && args[1] == "--socket",
        "usage: qshd helper-status --socket PATH"
    );
    let snapshot = query(std::path::Path::new(&args[2]))?;
    println!("{}", serde_json::to_string(&snapshot)?);
    Ok(())
}

#[cfg(all(test, target_os = "linux", feature = "system"))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    fn parent() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn helper_status143_endpoint_holds_lock_and_removes_only_its_socket() {
        let d = parent();
        let path = d.path().join("status.sock");
        let e = Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).unwrap();
        assert!(Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).is_err());
        std::fs::remove_file(&path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(e);
        assert!(path.exists());
        drop(replacement);
    }
    #[test]
    fn helper_status143_one_turn_sends_without_body_and_disconnect_is_not_fatal() {
        let d = parent();
        let path = d.path().join("status.sock");
        let mut e = Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).unwrap();
        e.service(|| panic!("idle status turns must not build a snapshot"))
            .unwrap();
        let gone = UnixStream::connect(&path).unwrap();
        drop(gone);
        e.service(|| b"{}".to_vec()).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        e.service(|| b"{\"schema\":2}".to_vec()).unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"{\"schema\":2}");
        e.service(|| b"{}".to_vec()).unwrap();
    }
    #[test]
    fn helper_status143_private_parent_and_existing_file_are_not_repaired() {
        let d = parent();
        let path = d.path().join("status.sock");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).is_err());
        assert_eq!(
            std::fs::metadata(d.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&path, b"owned fixture").unwrap();
        assert!(Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"owned fixture");
    }
    #[test]
    fn helper_status143_query_requires_complete_capped_compatible_response() {
        use std::io::Write;
        let valid = br#"{"schema":2,"phase":"serving","capacity":"unavailable","limit":256}"#;
        for (bytes, accepted) in [
            (valid.to_vec(), true),
            (b"{".to_vec(), false),
            (
                String::from_utf8(valid.to_vec())
                    .unwrap()
                    .replace("schema\":2", "schema\":1")
                    .into_bytes(),
                false,
            ),
            (vec![b' '; MAX_RESPONSE + 1], false),
        ] {
            let d = parent();
            let path = d.path().join("status.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let owner = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    match listener.accept() {
                        Ok((mut c, _)) => {
                            c.set_write_timeout(Some(std::time::Duration::from_secs(1)))
                                .unwrap();
                            let _ = c.write_all(&bytes);
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                break;
                            }
                            std::thread::yield_now();
                        }
                        Err(_) => break,
                    }
                }
            });
            let result = query_for(&path, nix::unistd::geteuid().as_raw());
            owner.join().unwrap();
            assert_eq!(result.is_ok(), accepted, "{result:?}");
        }
    }
    #[test]
    fn helper_status143_nonreaders_are_one_turn_clients_not_a_retained_queue() {
        let d = parent();
        let path = d.path().join("status.sock");
        let mut endpoint = Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).unwrap();
        let clients: Vec<_> = (0..8)
            .map(|_| UnixStream::connect(&path).unwrap())
            .collect();
        let mut snapshots = 0;
        endpoint
            .service(|| {
                snapshots += 1;
                vec![b' '; MAX_RESPONSE]
            })
            .unwrap();
        assert_eq!(snapshots, 1, "one helper turn accepts only one client");
        drop(clients);
        for _ in 0..8 {
            endpoint.service(|| b"{}".to_vec()).unwrap();
        }
        let mut client = UnixStream::connect(&path).unwrap();
        endpoint.service(|| b"{}".to_vec()).unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"{}");
    }
    #[test]
    fn helper_status143_disabled_diagnostics_keep_lifetime_lock_until_exit() {
        let d = parent();
        let path = d.path().join("status.sock");
        let mut endpoint = Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).unwrap();
        endpoint.disable();
        assert!(endpoint.fd().is_none());
        endpoint
            .service(|| panic!("disabled diagnostics must not perform query work"))
            .unwrap();
        assert!(Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).is_err());
        assert!(path.exists());
        drop(endpoint);
        assert!(!path.exists());
        drop(Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).unwrap());
    }
    #[test]
    fn selinux57_status_schema_keeps_semantic_failure_separate_from_custody() {
        let snapshot = Snapshot {
            schema: SCHEMA,
            phase: Phase::Serving,
            capacity: Capacity::Available,
            limit: 256,
            counts: Some(Counts {
                admitted: 0,
                provisional: 0,
                retiring: 0,
                retiring_pending: 0,
                charged: 0,
                unconfirmed: 0,
                missing_monitor: 0,
                wait_lost: 0,
                monitor_failed: 0,
                receipt_lost: 0,
                retired_slots: 0,
                wait_outstanding: 0,
                receipt_outstanding: 0,
                pam: Pam::NotOpened,
                cleanup_failure: Some(CleanupFailure::PtyLabelRestore { errno: 13 }),
            }),
        };
        let mut value = serde_json::to_value(&snapshot).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() <= MAX_RESPONSE);
        let counts = decode(&bytes).unwrap().counts.unwrap();
        assert_eq!(counts.charged, 0);
        assert_eq!(counts.unconfirmed, 0);
        assert_eq!(
            counts.cleanup_failure,
            Some(CleanupFailure::PtyLabelRestore { errno: 13 })
        );
        value["schema"] = serde_json::json!(1);
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["schema"] = serde_json::json!(SCHEMA);
        value["counts"]["cleanup_failure"]["operation"] = serde_json::json!("unknown");
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["counts"]["cleanup_failure"] = serde_json::Value::Null;
        assert!(decode(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .counts
            .unwrap()
            .cleanup_failure
            .is_none());
    }
}
