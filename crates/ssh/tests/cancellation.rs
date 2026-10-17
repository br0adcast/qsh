//! Controlled remote-action boundaries on real SSH connections.
mod support;

use client::channel::ChannelSubstrate;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::fake_server::{FakeAuth, FakeServer, ServerActivity};
use support::{CountingPrompter, NullEvents};
use transport::channel::{ChannelKind, OpenRequest};

fn params(server: &FakeServer) -> ssh::SshParams {
    ssh::SshParams {
        host: "127.0.0.1".into(),
        port: server.port,
        username: "test-user".into(),
        known_host_keys: vec![server.host_public_key_wire()],
        connect_timeout: Duration::from_secs(3),
        keepalive_interval: Duration::ZERO,
        compression: false,
        tcp_nodelay: true,
        knock: vec![],
    }
}

fn wait_for(mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(3);
    while !ready() {
        assert!(
            Instant::now() < until,
            "controlled SSH boundary was not reached"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[derive(Default)]
struct Refusals(AtomicUsize);
impl ssh::SshEvents for Refusals {
    fn on_channel(&self, event: client::channel::SubstrateEvent) {
        if matches!(event, client::channel::SubstrateEvent::Refused { .. }) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn on_closed(&self, _: String) {}
}

#[test]
fn cancellation_during_channel_open_prevents_remote_exec() {
    for cancelled in [false, true] {
        let activity = Arc::new(ServerActivity::default());
        let gate = Arc::new(tokio::sync::Notify::new());
        let server = FakeServer::start(FakeAuth {
            password: Some("test-password".into()),
            activity: activity.clone(),
            open_gate: Some(gate.clone()),
            exec_outputs: vec![b"done".to_vec()],
            ..Default::default()
        });
        let cancel = knock::Cancel::new();
        let refusals = Arc::new(Refusals::default());
        let (connection, mut substrate) = ssh::connect(
            params(&server),
            ssh::SshAuthPlan::single(ssh::AuthMethod::Password(
                "test-password".to_string().into(),
            )),
            Arc::new(knock::NoBind),
            refusals.clone(),
            &cancel,
        )
        .unwrap();
        substrate.open(&OpenRequest {
            stream: 16,
            kind: ChannelKind::Command,
            cols: 0,
            rows: 0,
            screen: false,
            command: b"must not run after cancellation".to_vec(),
        });
        wait_for(|| server.sftp_channels.opened.load(Ordering::SeqCst) == 1);
        assert_eq!(activity.exec.load(Ordering::SeqCst), 0);
        if cancelled {
            cancel.cancel();
        }
        gate.notify_one();
        if cancelled {
            // Keep the connection owner alive: this tests the actual dispatcher,
            // not caller cleanup winning a race with channel acceptance.
            wait_for(|| {
                refusals.0.load(Ordering::SeqCst) == 1 || activity.exec.load(Ordering::SeqCst) != 0
            });
            assert_eq!(
                activity.exec.load(Ordering::SeqCst),
                0,
                "stale exec crossed channel-open boundary"
            );
            assert_eq!(refusals.0.load(Ordering::SeqCst), 1);
            assert!(!connection.is_closed());

            // Cleanup has its own explicit authorization. It does not revive
            // the default generation or permit its start/allowlist commands.
            let mut cleanup = substrate.with_cancel(&knock::Cancel::new());
            cleanup.open(&OpenRequest {
                stream: 17,
                kind: ChannelKind::Command,
                cols: 0,
                rows: 0,
                screen: false,
                command: b"remove owned staging file".to_vec(),
            });
            wait_for(|| server.sftp_channels.opened.load(Ordering::SeqCst) == 2);
            gate.notify_one();
            wait_for(|| activity.exec.load(Ordering::SeqCst) == 1);
            for (stream, command) in [(18, "start daemon"), (19, "update allowlist")] {
                substrate.open(&OpenRequest {
                    stream,
                    kind: ChannelKind::Command,
                    cols: 0,
                    rows: 0,
                    screen: false,
                    command: command.as_bytes().to_vec(),
                });
            }
            wait_for(|| refusals.0.load(Ordering::SeqCst) == 3);
            assert_eq!(server.sftp_channels.opened.load(Ordering::SeqCst), 2);
            assert_eq!(activity.exec.load(Ordering::SeqCst), 1);
        } else {
            wait_for(|| activity.exec.load(Ordering::SeqCst) == 1);
        }
        connection.close();
    }
}

#[test]
fn cancellation_during_method_discovery_prevents_next_userauth() {
    for cancelled in [false, true] {
        let activity = Arc::new(ServerActivity::default());
        let gate = Arc::new(tokio::sync::Notify::new());
        let server = FakeServer::start(FakeAuth {
            password: Some("test-password".into()),
            activity: activity.clone(),
            auth_none_gate: Some(gate.clone()),
            ..Default::default()
        });
        let parameters = params(&server);
        let cancel = knock::Cancel::new();
        let worker_cancel = cancel.clone();
        let login = std::thread::spawn(move || {
            ssh::connect(
                parameters,
                ssh::SshAuthPlan {
                    methods: vec![ssh::AuthMethod::AskPassword],
                    prompter: Arc::new(CountingPrompter::answering_password("test-password")),
                },
                Arc::new(knock::NoBind),
                Arc::new(NullEvents),
                &worker_cancel,
            )
        });
        wait_for(|| activity.userauth.load(Ordering::SeqCst) == 1);
        if cancelled {
            cancel.cancel();
        }
        gate.notify_one();
        let result = login.join().unwrap();
        if cancelled {
            assert!(
                matches!(result, Err(ssh::SshError::Cancelled)),
                "cancelled login must not succeed"
            );
            assert_eq!(
                activity.userauth.load(Ordering::SeqCst),
                1,
                "next auth crossed the cancelled generation"
            );
        } else {
            let (connection, _) = result.unwrap();
            assert_eq!(activity.userauth.load(Ordering::SeqCst), 2);
            connection.close();
        }
        assert_eq!(activity.exec.load(Ordering::SeqCst), 0);
    }
}

struct DelayedSigner {
    key: support::SoftSigner,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl ssh::ExternalSigner for DelayedSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.key.public_wire())
    }
    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.entered.send(()).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        ssh::ExternalSigner::sign_ssh(&self.key, data)
    }
}

#[test]
fn cancellation_while_signing_prevents_the_signed_userauth_request() {
    for cancelled in [false, true] {
        let activity = Arc::new(ServerActivity::default());
        let server = FakeServer::start(FakeAuth {
            accept_any_key: true,
            activity: activity.clone(),
            ..Default::default()
        });
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let signer = DelayedSigner {
            key: support::SoftSigner::random(),
            entered,
            release: std::sync::Mutex::new(released),
        };
        let parameters = params(&server);
        let cancel = knock::Cancel::new();
        let worker_cancel = cancel.clone();
        let login = std::thread::spawn(move || {
            ssh::connect(
                parameters,
                ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
                Arc::new(knock::NoBind),
                Arc::new(NullEvents),
                &worker_cancel,
            )
        });
        waiting.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(activity.userauth.load(Ordering::SeqCst), 1);
        if cancelled {
            cancel.cancel();
        }
        release.send(()).unwrap();
        let result = login.join().unwrap();
        if cancelled {
            assert!(matches!(result, Err(ssh::SshError::Cancelled)));
            assert_eq!(
                activity.userauth.load(Ordering::SeqCst),
                1,
                "cancelled signature must not reach the server"
            );
        } else {
            let (connection, _) = result.unwrap();
            assert_eq!(activity.userauth.load(Ordering::SeqCst), 2);
            connection.close();
        }
    }
}

#[test]
fn cancellation_during_private_key_offer_prevents_automatic_signature_dispatch() {
    for cancelled in [false, true] {
        let activity = Arc::new(ServerActivity::default());
        let gate = Arc::new(tokio::sync::Notify::new());
        let server = FakeServer::start(FakeAuth {
            accept_any_key: true,
            activity: activity.clone(),
            publickey_offer_gate: Some(gate.clone()),
            ..Default::default()
        });
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
        let parameters = params(&server);
        let cancel = knock::Cancel::new();
        let worker_cancel = cancel.clone();
        let login = std::thread::spawn(move || {
            ssh::connect(
                parameters,
                ssh::SshAuthPlan::single(ssh::AuthMethod::PrivateKeyPem(pem.into())),
                Arc::new(knock::NoBind),
                Arc::new(NullEvents),
                &worker_cancel,
            )
        });
        wait_for(|| activity.userauth.load(Ordering::SeqCst) == 1);
        if cancelled {
            cancel.cancel();
        }
        gate.notify_one();
        let result = login.join().unwrap();
        if cancelled {
            assert!(matches!(result, Err(ssh::SshError::Cancelled)));
            assert_eq!(
                activity.userauth.load(Ordering::SeqCst),
                1,
                "russh must not sign automatically after cancellation"
            );
        } else {
            let (connection, _) = result.unwrap();
            assert_eq!(activity.userauth.load(Ordering::SeqCst), 2);
            connection.close();
        }
    }
}
