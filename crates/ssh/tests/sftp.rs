mod support;

use std::fs;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ssh::{SshConnection, SshError, TransferLimits, UploadProgress};
use support::fake_server::{FakeAuth, FakeServer, SftpBehavior};
use support::*;

struct Recorder;
impl ssh::SshEvents for Recorder {
    fn on_channel(&self, _: client::channel::SubstrateEvent) {}
    fn on_closed(&self, _: String) {}
}

#[derive(Default)]
struct Progress(Mutex<Vec<(u64, u64)>>);
impl UploadProgress for Progress {
    fn uploaded(&self, bytes: u64, total: u64) {
        self.0.lock().unwrap().push((bytes, total));
    }
}

fn limits() -> TransferLimits {
    TransferLimits {
        total: Duration::from_secs(5),
        idle: Duration::from_secs(2),
        max_bytes: 1024 * 1024,
    }
}

fn real() -> Option<(TestSshd, SshConnection)> {
    sshd_or_skip()?;
    let keys = tempfile::tempdir().unwrap();
    let (key, public) = keygen_file("ed25519", keys.path());
    let home = tempfile::Builder::new()
        .prefix("qsh home ")
        .tempdir()
        .unwrap();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![public],
        session_env: vec![("HOME".into(), home.path().to_str().unwrap().into())],
        ..Default::default()
    });
    sftp_probe(&sshd, &key);
    let (connection, _) = ssh::connect(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::PrivateKeyPem(ssh::Zeroizing::new(
            fs::read_to_string(key).unwrap(),
        ))),
        Arc::new(knock::NoBind),
        Arc::new(Recorder),
        &knock::Cancel::new(),
    )
    .unwrap();
    Some((sshd, connection))
}

fn fake(behavior: SftpBehavior) -> (FakeServer, SshConnection) {
    fake_with(FakeAuth {
        password: Some("test".into()),
        sftp: Some(behavior),
        ..Default::default()
    })
}

fn fake_with(auth: FakeAuth) -> (FakeServer, SshConnection) {
    let server = FakeServer::start(auth);
    let (connection, _) = ssh::connect(
        ssh::SshParams {
            host: "127.0.0.1".into(),
            port: server.port,
            username: "test".into(),
            known_host_keys: vec![server.host_public_key_wire()],
            connect_timeout: Duration::from_secs(3),
            keepalive_interval: Duration::ZERO,
            compression: false,
            tcp_nodelay: true,
            knock: vec![],
        },
        ssh::SshAuthPlan::single(ssh::AuthMethod::Password(ssh::Zeroizing::new(
            "test".into(),
        ))),
        Arc::new(knock::NoBind),
        Arc::new(Recorder),
        &knock::Cancel::new(),
    )
    .unwrap();
    (server, connection)
}

fn wait_for_counter(counter: &std::sync::atomic::AtomicUsize, target: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) < target && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(counter.load(Ordering::SeqCst) >= target);
}

#[test]
fn cancelled_pending_open_closes_its_late_confirmed_channel() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (server, connection) = fake_with(FakeAuth {
        password: Some("test".into()),
        sftp: Some(SftpBehavior::Successful),
        open_gate: Some(gate.clone()),
        ..Default::default()
    });
    let sandbox = tempfile::tempdir().unwrap();
    let cancel = knock::Cancel::new();
    std::thread::scope(|scope| {
        let upload = scope.spawn(|| {
            connection.upload_file(
                sandbox.path().join("late").to_str().unwrap(),
                Arc::from(&b"bytes"[..]),
                limits(),
                Arc::new(Progress::default()),
                &cancel,
            )
        });
        wait_for_counter(&server.sftp_channels.opened, 1);
        cancel.cancel();
        std::thread::sleep(Duration::from_millis(40));
        gate.notify_one();
        assert!(matches!(upload.join().unwrap(), Err(SshError::Cancelled)));
    });
    wait_for_counter(&server.sftp_channels.closed, 1);
    assert!(!connection.is_closed());
    assert_eq!(server.sftp_channels.requested.load(Ordering::SeqCst), 0);
    connection.close();
}

#[test]
fn cancelled_unconfirmed_open_closes_the_connection_after_bounded_cleanup() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let (server, connection) = fake_with(FakeAuth {
        password: Some("test".into()),
        sftp: Some(SftpBehavior::Successful),
        open_gate: Some(gate),
        ..Default::default()
    });
    let sandbox = tempfile::tempdir().unwrap();
    let cancel = knock::Cancel::new();
    std::thread::scope(|scope| {
        let upload = scope.spawn(|| {
            connection.upload_file(
                sandbox.path().join("never-confirmed").to_str().unwrap(),
                Arc::from(&b"bytes"[..]),
                limits(),
                Arc::new(Progress::default()),
                &cancel,
            )
        });
        wait_for_counter(&server.sftp_channels.opened, 1);
        let started = Instant::now();
        cancel.cancel();
        assert!(matches!(upload.join().unwrap(), Err(SshError::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(1));
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !connection.is_closed() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        connection.is_closed(),
        "an ownerless pending open kept its SSH connection alive"
    );
    assert_eq!(server.sftp_channels.requested.load(Ordering::SeqCst), 0);
}

#[test]
fn early_status_cannot_queue_an_image_behind_a_stopped_writer() {
    let (server, connection) = fake(SftpBehavior::EarlyStatus);
    let sandbox = tempfile::tempdir().unwrap();
    let cancel = knock::Cancel::new();
    let progress = Arc::new(Progress::default());
    std::thread::scope(|scope| {
        let upload = scope.spawn(|| {
            connection.upload_file(
                sandbox.path().join("early").to_str().unwrap(),
                Arc::from(vec![b'x'; 8 * 1024 * 1024]),
                TransferLimits {
                    max_bytes: 8 * 1024 * 1024,
                    ..limits()
                },
                progress.clone(),
                &cancel,
            )
        });
        wait_for_counter(&server.sftp_channels.status_rounds, 500);
        let acknowledged = progress
            .0
            .lock()
            .unwrap()
            .last()
            .map_or(0, |&(done, _)| done);
        cancel.cancel();
        let result = upload.join().unwrap();
        assert_eq!(
            acknowledged, 0,
            "an unsent image advanced through fabricated STATUS replies"
        );
        assert!(matches!(result, Err(SshError::Cancelled)), "{result:?}");
    });
    assert_eq!(server.sftp_channels.writes.load(Ordering::SeqCst), 0);
    connection.close();
}

#[test]
fn successful_upload_accepts_ping_rtt_above_emergency_cleanup_timeout() {
    let (_server, connection) = fake_with(FakeAuth {
        password: Some("test".into()),
        sftp: Some(SftpBehavior::Successful),
        read_delay: Duration::from_millis(350),
        ..Default::default()
    });
    let sandbox = tempfile::tempdir().unwrap();
    let progress = Arc::new(Progress::default());
    let started = Instant::now();
    let result = connection.upload_file(
        sandbox.path().join("slow-ping").to_str().unwrap(),
        Arc::from(&b"bytes"[..]),
        TransferLimits {
            total: Duration::from_secs(10),
            idle: Duration::from_secs(2),
            max_bytes: 5,
        },
        progress.clone(),
        &knock::Cancel::new(),
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(progress.0.lock().unwrap().last(), Some(&(5, 5)));
    assert!(started.elapsed() < Duration::from_secs(10));
    connection.close();
}

#[test]
fn upload_preserves_exact_bytes() {
    let Some((sshd, connection)) = real() else {
        return;
    };
    let destination = sshd.dir.path().join("upload with spaces");
    let payload: Vec<u8> = (0..180_013).map(|n| (n % 256) as u8).collect();
    let progress = Arc::new(Progress::default());
    connection
        .upload_file(
            destination.to_str().unwrap(),
            payload.clone().into(),
            limits(),
            progress.clone(),
            &knock::Cancel::new(),
        )
        .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), payload);
    let acknowledged = progress.0.lock().unwrap().last().unwrap().0;
    assert_eq!(acknowledged, payload.len() as u64);
    assert!(progress
        .0
        .lock()
        .unwrap()
        .iter()
        .all(|&(done, total)| done <= total && total == payload.len() as u64));
    connection.close();
}

#[test]
fn upload_refuses_existing_file() {
    let Some((sshd, connection)) = real() else {
        return;
    };
    let occupied = sshd.dir.path().join("occupied");
    fs::write(&occupied, b"original").unwrap();
    let progress = Arc::new(Progress::default());
    assert!(connection
        .upload_file(
            occupied.to_str().unwrap(),
            Arc::from(&b"replacement"[..]),
            limits(),
            progress.clone(),
            &knock::Cancel::new()
        )
        .is_err());
    assert_eq!(fs::read(&occupied).unwrap(), b"original");
    assert!(progress.0.lock().unwrap().is_empty());
    connection.close();
}

#[test]
fn stalled_sftp_is_cancelled() {
    let (_server, connection) = fake(SftpBehavior::Stalled);
    let sandbox = tempfile::tempdir().unwrap();
    let cancel = knock::Cancel::new();
    let trigger = cancel.clone();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        trigger.cancel();
    });
    let start = Instant::now();
    let cancelled = connection.upload_file(
        sandbox.path().join("stalled").to_str().unwrap(),
        Arc::from(&b"bytes"[..]),
        limits(),
        Arc::new(Progress::default()),
        &cancel,
    );
    assert!(
        matches!(cancelled, Err(SshError::Cancelled)),
        "{cancelled:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    thread.join().unwrap();
    connection.close();
}

#[test]
fn sftp_denied_is_not_a_success() {
    let (_server, connection) = fake(SftpBehavior::Denied);
    let sandbox = tempfile::tempdir().unwrap();
    let progress = Arc::new(Progress::default());
    assert!(connection
        .upload_file(
            sandbox.path().join("denied").to_str().unwrap(),
            Arc::from(&b"bytes"[..]),
            limits(),
            progress.clone(),
            &knock::Cancel::new()
        )
        .is_err());
    assert!(progress.0.lock().unwrap().is_empty());
    connection.close();
}

#[test]
fn cancelling_a_blocked_writer_closes_its_channel_and_releases_the_upload_slot() {
    let (server, connection) = fake(SftpBehavior::Stalled);
    let sandbox = tempfile::tempdir().unwrap();
    for attempt in 1..=20 {
        let cancel = knock::Cancel::new();
        std::thread::scope(|scope| {
            let upload = scope.spawn(|| {
                connection.upload_file(
                    sandbox.path().join("blocked").to_str().unwrap(),
                    Arc::from(&b"bytes"[..]),
                    limits(),
                    Arc::new(Progress::default()),
                    &cancel,
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while server.sftp_channels.requested.load(Ordering::SeqCst) < attempt
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                server.sftp_channels.requested.load(Ordering::SeqCst),
                attempt
            );
            assert!(matches!(
                connection.upload_file(
                    sandbox.path().join("parallel").to_str().unwrap(),
                    Arc::from(&b"bytes"[..]),
                    limits(),
                    Arc::new(Progress::default()),
                    &knock::Cancel::new(),
                ),
                Err(SshError::ResourceLimit(_))
            ));
            cancel.cancel();
            assert!(matches!(upload.join().unwrap(), Err(SshError::Cancelled)));
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while server.sftp_channels.closed.load(Ordering::SeqCst) < attempt
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            server.sftp_channels.closed.load(Ordering::SeqCst),
            attempt,
            "the cancelled stream worker retained its channel"
        );
        assert!(!connection.is_closed());
    }
    connection.close();
}

#[test]
fn stalled_sftp_obeys_both_total_and_idle_limits() {
    let (_server, connection) = fake(SftpBehavior::Stalled);
    let sandbox = tempfile::tempdir().unwrap();
    for (total, idle) in [
        (Duration::from_millis(100), Duration::from_secs(3)),
        (Duration::from_secs(3), Duration::from_millis(100)),
    ] {
        let started = Instant::now();
        let result = connection.upload_file(
            sandbox.path().join("timeout").to_str().unwrap(),
            Arc::from(&b"bytes"[..]),
            TransferLimits {
                total,
                idle,
                max_bytes: 5,
            },
            Arc::new(Progress::default()),
            &knock::Cancel::new(),
        );
        assert!(matches!(result, Err(SshError::Protocol(_))), "{result:?}");
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    connection.close();
}

#[test]
fn invalid_inputs_do_not_open_a_subsystem_or_create_a_file() {
    let (server, connection) = fake(SftpBehavior::Denied);
    let sandbox = tempfile::tempdir().unwrap();
    let destination = sandbox.path().join("limit");
    let payload: Arc<[u8]> = Arc::from(&b"bytes"[..]);
    assert!(matches!(
        connection.upload_file(
            destination.to_str().unwrap(),
            payload.clone(),
            TransferLimits {
                max_bytes: 4,
                ..limits()
            },
            Arc::new(Progress::default()),
            &knock::Cancel::new()
        ),
        Err(SshError::ResourceLimit(_))
    ));
    assert!(matches!(
        connection.upload_file(
            "relative/path",
            payload.clone(),
            limits(),
            Arc::new(Progress::default()),
            &knock::Cancel::new()
        ),
        Err(SshError::Protocol(_))
    ));
    let cancel = knock::Cancel::new();
    cancel.cancel();
    assert!(matches!(
        connection.upload_file(
            destination.to_str().unwrap(),
            payload,
            limits(),
            Arc::new(Progress::default()),
            &cancel
        ),
        Err(SshError::Cancelled)
    ));
    assert_eq!(server.sftp_channels.requested.load(Ordering::SeqCst), 0);
    assert!(!destination.exists());
    connection.close();
}

#[test]
fn unacknowledged_write_reports_no_progress_and_is_cancelled() {
    let (server, connection) = fake(SftpBehavior::WriteStalled);
    let sandbox = tempfile::tempdir().unwrap();
    let progress = Arc::new(Progress::default());
    let cancel = knock::Cancel::new();
    std::thread::scope(|scope| {
        let upload = scope.spawn(|| {
            connection.upload_file(
                sandbox.path().join("unacknowledged").to_str().unwrap(),
                Arc::from(vec![b'x'; 96 * 1024]),
                limits(),
                progress.clone(),
                &cancel,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.sftp_channels.writes.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(server.sftp_channels.writes.load(Ordering::SeqCst), 1);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            server.sftp_channels.writes.load(Ordering::SeqCst),
            1,
            "more than one unacknowledged write"
        );
        assert!(progress.0.lock().unwrap().is_empty());
        cancel.cancel();
        assert!(matches!(upload.join().unwrap(), Err(SshError::Cancelled)));
    });
    assert!(!connection.is_closed());
    connection.close();
}

#[test]
fn oversized_sftp_packet_is_refused_before_reading_its_body() {
    let (_server, connection) = fake(SftpBehavior::OversizedReply);
    let sandbox = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let result = connection.upload_file(
        sandbox.path().join("oversized").to_str().unwrap(),
        Arc::from(&b"bytes"[..]),
        limits(),
        Arc::new(Progress::default()),
        &knock::Cancel::new(),
    );
    assert!(matches!(result, Err(SshError::Protocol(_))), "{result:?}");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "waited for an oversized body"
    );
    connection.close();
}
