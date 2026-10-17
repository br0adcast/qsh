//! Keys in this file are synthetic public wire blobs, never service credentials.
use std::fs;
use std::sync::{Arc, Barrier};

use connect::recovery_gate::RecoveryEpoch;
use connect::server_identity::{ServerIdentity, SshBinding, SshEndpoint};
use qsh::ssh_bindings::{BindingError, SshBindings, TrustWritePermit};

fn binding(key: u8) -> SshBinding {
    // RFC 4253 string("ssh-ed25519"), string(32 synthetic public bytes).
    let mut host_key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    host_key.extend([key; 32]);
    SshBinding {
        server: ServerIdentity {
            qsh_key: [7; 32],
            username: "test-user".into(),
        },
        endpoint: SshEndpoint {
            host: "host.example".into(),
            port: 22,
        },
        host_key,
    }
}

fn permit() -> TrustWritePermit {
    TrustWritePermit::new(RecoveryEpoch {
        connection: 1,
        network: 2,
    })
}

#[test]
fn binding_is_scoped_to_server_user_and_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    let store = SshBindings::open(path.clone());
    let first = binding(1);
    store.grant(&first, &permit()).unwrap();
    let store = SshBindings::open(path);
    assert_eq!(
        store.allowed(&first.server, &first.endpoint).unwrap(),
        vec![first.host_key.clone()]
    );
    let mut other = first.clone();
    other.server.qsh_key = [8; 32];
    assert!(store
        .allowed(&other.server, &other.endpoint)
        .unwrap()
        .is_empty());
    other = first.clone();
    other.server.username = "other-user".into();
    assert!(store
        .allowed(&other.server, &other.endpoint)
        .unwrap()
        .is_empty());
    other = first.clone();
    other.endpoint.port = 2222;
    assert!(store
        .allowed(&other.server, &other.endpoint)
        .unwrap()
        .is_empty());
    other = first;
    other.endpoint.host = "other.example".into();
    assert!(store
        .allowed(&other.server, &other.endpoint)
        .unwrap()
        .is_empty());
}

#[test]
fn known_hosts_does_not_create_a_binding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    let legacy = dir.path().join("known_hosts");
    let record = binding(1);
    sshauth::known_hosts::KnownHosts::open(legacy.clone())
        .pin("host.example", 22, &record.server.qsh_key)
        .unwrap();
    let original = fs::read(&legacy).unwrap();
    let count = fs::read_dir(dir.path()).unwrap().count();
    let store = SshBindings::open(path.clone());
    assert!(store
        .allowed(&record.server, &record.endpoint)
        .unwrap()
        .is_empty());
    assert!(!path.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), count);
    store.grant(&record, &permit()).unwrap();
    assert_eq!(fs::read(legacy).unwrap(), original);
}

#[test]
fn concurrent_grants_keep_both_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/ssh_bindings.json");
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = [1, 2]
        .into_iter()
        .map(|key| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                SshBindings::open(path)
                    .grant(&binding(key), &permit())
                    .unwrap();
            })
        })
        .collect();
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let store = SshBindings::open(path);
    let record = binding(1);
    let keys = store.allowed(&record.server, &record.endpoint).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&binding(1).host_key));
    assert!(keys.contains(&binding(2).host_key));
    store.grant(&record, &permit()).unwrap();
    assert_eq!(
        store
            .allowed(&record.server, &record.endpoint)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn cancel_before_commit_does_not_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    let store = SshBindings::open(path.clone());
    let authorization = permit();
    authorization.clone().invalidate();
    assert!(matches!(
        store.grant(&binding(1), &authorization),
        Err(BindingError::Cancelled)
    ));
    assert!(!path.exists());
    let valid = permit();
    store.grant(&binding(1), &valid).unwrap();
    let before = fs::read(&path).unwrap();
    valid.invalidate();
    assert!(matches!(
        store.grant(&binding(2), &valid),
        Err(BindingError::Cancelled)
    ));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn malformed_store_never_enables_ssh() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    let record = binding(1);
    let store = SshBindings::open(path.clone());
    store.grant(&record, &permit()).unwrap();
    let valid: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut bad_key = valid.clone();
    bad_key["bindings"][0]["host_key"] = serde_json::json!([0, 1, 2]);
    let mut bad_port = valid.clone();
    bad_port["bindings"][0]["port"] = serde_json::json!(0);
    let mut mixed = valid.clone();
    mixed["bindings"]
        .as_array_mut()
        .unwrap()
        .push(bad_key["bindings"][0].clone());
    let mut unknown_field = valid.clone();
    unknown_field["unrecognized"] = serde_json::json!(true);
    for corrupt in [
        b"not json".to_vec(),
        b"{}".to_vec(),
        serde_json::to_vec(&bad_key).unwrap(),
        serde_json::to_vec(&bad_port).unwrap(),
        serde_json::to_vec(&unknown_field).unwrap(),
        serde_json::to_vec(&mixed).unwrap(),
        b"{\"version\":1,\"version\":1,\"bindings\":[]}".to_vec(),
    ] {
        fs::write(&path, &corrupt).unwrap();
        assert!(matches!(
            store.allowed(&record.server, &record.endpoint),
            Err(BindingError::InvalidFormat)
        ));
        assert!(matches!(
            store.grant(&binding(2), &permit()),
            Err(BindingError::InvalidFormat)
        ));
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    }
    let mut future = valid;
    future["version"] = serde_json::json!(2);
    fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(matches!(
        store.allowed(&record.server, &record.endpoint),
        Err(BindingError::UnsupportedVersion)
    ));
    assert!(matches!(
        store.grant(&record, &permit()),
        Err(BindingError::UnsupportedVersion)
    ));
}

#[test]
fn invalid_grants_do_not_create_a_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    let store = SshBindings::open(path.clone());
    let mut invalid = binding(1);
    invalid.endpoint.port = 0;
    assert!(matches!(
        store.grant(&invalid, &permit()),
        Err(BindingError::InvalidFormat)
    ));
    invalid = binding(1);
    invalid.host_key.truncate(20);
    assert!(matches!(
        store.grant(&invalid, &permit()),
        Err(BindingError::InvalidFormat)
    ));
    invalid = binding(1);
    invalid.host_key.push(0);
    assert!(matches!(
        store.grant(&invalid, &permit()),
        Err(BindingError::InvalidFormat)
    ));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn store_and_lock_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    SshBindings::open(path.clone())
        .grant(&binding(1), &permit())
        .unwrap();
    for path in [path, dir.path().join(".ssh_bindings.json.lock")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn write_failure_is_reported_without_orphan_temps() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("not-a-directory");
    fs::write(&parent, "keep").unwrap();
    let store = SshBindings::open(parent.join("ssh_bindings.json"));
    assert!(matches!(
        store.grant(&binding(1), &permit()),
        Err(BindingError::Io(_))
    ));
    assert_eq!(fs::read_to_string(parent).unwrap(), "keep");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn cancellation_while_waiting_for_another_writer_prevents_commit() {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_bindings.json");
    let store = SshBindings::open(path.clone());
    store.grant(&binding(1), &permit()).unwrap();
    let before = fs::read(&path).unwrap();
    let lock = OpenOptions::new()
        .write(true)
        .open(dir.path().join(".ssh_bindings.json.lock"))
        .unwrap();
    // SAFETY: this test owns the open fd until the worker has finished.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let authorization = permit();
    let worker_permit = authorization.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        done_tx
            .send(store.grant(&binding(2), &worker_permit))
            .unwrap();
    });
    started_rx.recv().unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    authorization.invalidate();
    // SAFETY: the test still owns this open fd.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Err(BindingError::Cancelled)
    ));
    worker.join().unwrap();
    assert_eq!(fs::read(path).unwrap(), before);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_lock_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("unrelated");
    fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join(".ssh_bindings.json.lock")).unwrap();
    let path = dir.path().join("ssh_bindings.json");
    assert!(matches!(
        SshBindings::open(path.clone()).grant(&binding(1), &permit()),
        Err(BindingError::Io(_))
    ));
    assert!(!path.exists());
    assert_eq!(fs::read_to_string(target).unwrap(), "keep");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}
