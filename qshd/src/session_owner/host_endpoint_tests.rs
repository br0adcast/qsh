use super::host_endpoint::HostEndpoint;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

fn private_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn entries(path: &Path) -> BTreeSet<OsString> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

fn bind_socket(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn host_endpoint_publication_is_private_and_distinct() {
    let root = private_dir();
    for name in ["plain", "host-\u{2603}"] {
        let parent = root.path().join(name);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let control_path = parent.join("control.sock");
        let (_control, _control_cleanup) =
            crate::control::bind_private_owned(&control_path).unwrap();
        let control_identity = identity(&control_path);
        let endpoint = HostEndpoint::publish(&parent, Duration::ZERO).unwrap();
        let socket = parent.join("host-v1.sock");
        let socket_metadata = fs::metadata(&socket).unwrap();
        assert!(socket_metadata.file_type().is_socket());
        assert_eq!(socket_metadata.mode() & 0o7777, 0o600);
        assert_eq!(socket_metadata.uid(), nix::unistd::geteuid().as_raw());
        let lock = parent.join("host-v1.sock.lock");
        let lock_metadata = fs::metadata(&lock).unwrap();
        assert!(lock_metadata.is_file());
        assert_eq!(lock_metadata.mode() & 0o7777, 0o600);
        assert_eq!(lock_metadata.nlink(), 1);
        assert_eq!(lock_metadata.uid(), nix::unistd::geteuid().as_raw());
        assert!(UnixStream::connect(&socket).is_ok());
        drop(endpoint);
        assert!(!socket.exists());
        assert_eq!(identity(&lock), (lock_metadata.dev(), lock_metadata.ino()));
        assert_eq!(identity(&control_path), control_identity);
        assert!(UnixStream::connect(&control_path).is_ok());
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o700);
    }
}

#[test]
fn host_endpoint_rejects_unsafe_or_missing_parent_before_lock() {
    let root = private_dir();
    for mode in [0o755, 0o711, 0o1700] {
        let parent = root.path().join(format!("mode{mode:o}"));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
        fs::write(parent.join("sentinel"), b"directory sentinel").unwrap();
        let before = identity(&parent);
        assert!(HostEndpoint::publish(&parent, Duration::ZERO).is_err());
        assert_eq!(identity(&parent), before);
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, mode);
        assert_eq!(
            entries(&parent),
            BTreeSet::from([OsString::from("sentinel")])
        );
        assert_eq!(
            fs::read(parent.join("sentinel")).unwrap(),
            b"directory sentinel"
        );
    }
    let file = root.path().join("file");
    fs::write(&file, b"parent sentinel").unwrap();
    let dangling = root.path().join("dangling");
    symlink(root.path().join("missing"), &dangling).unwrap();
    let loop_a = root.path().join("loop-a");
    let loop_b = root.path().join("loop-b");
    symlink(&loop_b, &loop_a).unwrap();
    symlink(&loop_a, &loop_b).unwrap();
    let before = entries(root.path());
    for parent in [root.path().join("missing"), file.clone(), dangling, loop_a] {
        assert!(HostEndpoint::publish(&parent, Duration::ZERO).is_err());
        assert_eq!(entries(root.path()), before);
    }
    assert_eq!(fs::read(&file).unwrap(), b"parent sentinel");
    let private = root.path().join("private");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.path().join("trusted-alias");
    symlink(&private, &alias).unwrap();
    let alias_identity = identity(&alias);
    let endpoint = HostEndpoint::publish(&alias, Duration::ZERO).unwrap();
    assert!(UnixStream::connect(alias.join("host-v1.sock")).is_ok());
    drop(endpoint);
    assert!(!private.join("host-v1.sock").exists());
    assert_eq!(identity(&alias), alias_identity);
    assert_eq!(fs::metadata(&private).unwrap().mode() & 0o7777, 0o700);
}

#[test]
fn host_endpoint_never_replaces_an_existing_entry() {
    for kind in ["live", "stale", "file", "symlink"] {
        let root = private_dir();
        let socket = root.path().join("host-v1.sock");
        let sentinel = root.path().join("sentinel");
        fs::write(&sentinel, b"outside sentinel").unwrap();
        let _listener = match kind {
            "live" => Some(bind_socket(&socket)),
            "stale" => {
                drop(bind_socket(&socket));
                None
            }
            "file" => {
                fs::write(&socket, b"existing file").unwrap();
                None
            }
            "symlink" => {
                symlink(&sentinel, &socket).unwrap();
                None
            }
            _ => unreachable!(),
        };
        let before = fs::symlink_metadata(&socket).unwrap();
        assert!(HostEndpoint::publish(root.path(), Duration::ZERO).is_err());
        let after = fs::symlink_metadata(&socket).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.mode(), before.mode());
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside sentinel");
        match kind {
            "live" => assert!(UnixStream::connect(&socket).is_ok()),
            "stale" => assert!(UnixStream::connect(&socket).is_err()),
            "file" => assert_eq!(fs::read(&socket).unwrap(), b"existing file"),
            "symlink" => assert_eq!(fs::read_link(&socket).unwrap(), sentinel),
            _ => unreachable!(),
        }
        assert!(entries(root.path()).iter().all(|name| {
            use std::os::unix::ffi::OsStrExt;
            !name.as_os_str().as_bytes().starts_with(b".c")
        }));
    }
}

#[test]
fn host_endpoint_holds_lock_through_publication_lifetime() {
    let root = private_dir();
    let socket = root.path().join("host-v1.sock");
    let lock = root.path().join("host-v1.sock.lock");
    let first = HostEndpoint::publish(root.path(), Duration::ZERO).unwrap();
    let lock_identity = identity(&lock);
    let contender = HostEndpoint::publish(root.path(), Duration::ZERO)
        .err()
        .unwrap();
    assert_eq!(contender.kind(), std::io::ErrorKind::TimedOut);
    assert!(UnixStream::connect(&socket).is_ok());
    assert_eq!(identity(&lock), lock_identity);
    drop(first);
    assert!(!socket.exists());
    let later = HostEndpoint::publish(root.path(), Duration::ZERO).unwrap();
    assert_eq!(identity(&lock), lock_identity);
    assert!(UnixStream::connect(&socket).is_ok());
    drop(later);
    assert!(!socket.exists());
    assert_eq!(identity(&lock), lock_identity);
}

#[test]
fn host_endpoint_cleanup_retains_original_parent() {
    let root = private_dir();
    let parent = root.path().join("private");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = HostEndpoint::publish(&parent, Duration::ZERO).unwrap();
    let moved = root.path().join("retained");
    fs::rename(&parent, &moved).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = parent.join("host-v1.sock");
    let _competitor = bind_socket(&replacement);
    let replacement_identity = identity(&replacement);
    fs::write(parent.join("sentinel"), b"replacement sentinel").unwrap();
    assert!(endpoint.refuse_unprovisioned().is_err());
    drop(endpoint);
    assert!(!moved.join("host-v1.sock").exists());
    assert!(moved.join("host-v1.sock.lock").is_file());
    assert_eq!(identity(&replacement), replacement_identity);
    assert!(UnixStream::connect(&replacement).is_ok());
    assert_eq!(
        fs::read(parent.join("sentinel")).unwrap(),
        b"replacement sentinel"
    );
    assert_eq!(
        entries(&parent),
        BTreeSet::from([OsString::from("host-v1.sock"), OsString::from("sentinel"),])
    );
}

#[test]
fn host_endpoint_cleanup_preserves_replaced_socket() {
    let root = private_dir();
    let endpoint = HostEndpoint::publish(root.path(), Duration::ZERO).unwrap();
    let socket = root.path().join("host-v1.sock");
    fs::remove_file(&socket).unwrap();
    let _competitor = bind_socket(&socket);
    let replacement_identity = identity(&socket);
    drop(endpoint);
    assert_eq!(identity(&socket), replacement_identity);
    assert!(UnixStream::connect(&socket).is_ok());
    assert!(root.path().join("host-v1.sock.lock").is_file());
}

fn client(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn closed_without_reply(stream: &mut UnixStream) -> bool {
    use std::io::{ErrorKind, Read};
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => true,
        Err(error) if error.kind() == ErrorKind::ConnectionReset => true,
        Err(error) if error.kind() == ErrorKind::WouldBlock => false,
        other => panic!("unprovisioned stream must close without a reply: {other:?}"),
    }
}

#[test]
fn host_endpoint_refuses_silent_unprovisioned_connection() {
    let root = private_dir();
    let endpoint = HostEndpoint::publish(root.path(), Duration::ZERO).unwrap();
    let mut peer = client(&root.path().join("host-v1.sock"));
    assert!(endpoint.refuse_unprovisioned().unwrap());
    assert!(closed_without_reply(&mut peer));
    assert!(!endpoint.refuse_unprovisioned().unwrap());
}

#[test]
fn host_endpoint_refuses_protocol_bytes_without_dispatch() {
    use std::io::Write;
    let root = private_dir();
    let endpoint = HostEndpoint::publish(root.path(), Duration::ZERO).unwrap();
    let socket = root.path().join("host-v1.sock");
    let mut peer = client(&socket);
    peer.write_all(b"QSHH\x00\xffunprovisioned").unwrap();
    assert!(endpoint.refuse_unprovisioned().unwrap());
    assert!(closed_without_reply(&mut peer));
    let mut subsequent = client(&socket);
    assert!(endpoint.refuse_unprovisioned().unwrap());
    assert!(closed_without_reply(&mut subsequent));
    assert!(!endpoint.refuse_unprovisioned().unwrap());
}

#[test]
fn host_endpoint_refusal_consumes_one_connection_per_call() {
    let root = private_dir();
    let endpoint = HostEndpoint::publish(root.path(), Duration::ZERO).unwrap();
    let socket = root.path().join("host-v1.sock");
    let mut first = client(&socket);
    let mut second = client(&socket);
    first.set_nonblocking(true).unwrap();
    second.set_nonblocking(true).unwrap();
    assert!(endpoint.refuse_unprovisioned().unwrap());
    let closed = usize::from(closed_without_reply(&mut first))
        + usize::from(closed_without_reply(&mut second));
    assert_eq!(closed, 1, "one accepted seam is closed per call");
    assert!(endpoint.refuse_unprovisioned().unwrap());
    assert!(closed_without_reply(&mut first));
    assert!(closed_without_reply(&mut second));
    assert!(!endpoint.refuse_unprovisioned().unwrap());
}
