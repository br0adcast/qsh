#[path = "support/recovery_ssh.rs"]
mod fake;
mod support;
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use support::*;
#[test]
fn authorization_requires_an_ssh_endpoint_before_network() {
    let args = ["--authorize-ssh", "alice@127.0.0.1,nossh"].map(String::from);
    let error = qsh::args::parse_args(&args).unwrap_err().to_string();
    assert!(
        error.contains("--authorize-ssh requires an SSH address"),
        "{error}"
    );
}
#[test]
fn direct_qsh_without_flag_does_not_probe_ssh_or_create_bindings() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let home = tempfile::tempdir().unwrap();
    let ssh = fake::Server::start();
    let address = format!("127.0.0.1:{},ssh={}", daemon.port, ssh.port);
    let peer_key = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    sshauth::known_hosts::KnownHosts::open(home.path().join("qsh/known_hosts"))
        .pin("127.0.0.1", daemon.port, &peer_key)
        .unwrap();
    let mut client = spawn_qsh(&["-i", key.to_str().unwrap(), &address], home.path());
    let screen = screen(&client);
    live(&mut client, &screen);
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
    ssh.untouched();
    assert_eq!(
        ssh.activity
            .connections
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}
fn screen(client: &Client) -> Arc<Mutex<Vec<u8>>> {
    let out = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), out.clone());
    out
}
fn text(screen: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&screen.lock().unwrap()).into_owned()
}
fn wait(screen: &Arc<Mutex<Vec<u8>>>, needle: &str) {
    assert!(
        wait_until(|| text(screen).contains(needle)),
        "missing {needle}: {}",
        text(screen)
    );
}
fn live(client: &mut Client, screen: &Arc<Mutex<Vec<u8>>>) {
    client.type_line("echo AUTHORIZATION_'LIVE'");
    wait(screen, "AUTHORIZATION_LIVE");
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}
#[test]
fn explicit_authorization_displays_both_keys_and_grants_only_selected_pair() {
    authorize(b"yes\n", true, false);
}
#[test]
fn declining_binding_leaves_the_qsh_shell_usable() {
    authorize(b"no\n", false, false);
}
#[test]
fn enter_defaults_to_no_for_binding_consent() {
    authorize(b"\n", false, false);
}
#[test]
fn store_write_error_leaves_the_qsh_shell_usable() {
    authorize(b"yes\n", false, true);
}
#[test]
fn unreadable_ssh_store_prevents_explicit_authorization_probes() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let home = tempfile::tempdir().unwrap();
    let ssh = fake::Server::start();
    let path = home.path().join(".ssh/known_hosts");
    std::fs::create_dir_all(&path).unwrap();
    let peer_key = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    sshauth::known_hosts::KnownHosts::open(home.path().join("qsh/known_hosts"))
        .pin("127.0.0.1", daemon.port, &peer_key)
        .unwrap();
    let address = format!("127.0.0.1:{},ssh={}", daemon.port, ssh.port);
    let mut client = spawn_qsh(
        &["--authorize-ssh", "-i", key.to_str().unwrap(), &address],
        home.path(),
    );
    let output = screen(&client);
    wait(&output, "could not read SSH known-hosts file");
    let shown = text(&output);
    assert!(shown.contains(&path.display().to_string()), "{shown}");
    assert!(shown.contains("Is a directory"), "{shown}");
    assert!(!shown.contains("The authenticity of host"), "{shown}");
    assert!(!shown.contains("Authorize SSH recovery"), "{shown}");
    live(&mut client, &output);
    ssh.untouched();
    assert_eq!(
        ssh.activity
            .connections
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
}

fn authorize(answer: &[u8], accept: bool, store_error: bool) {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let home = tempfile::tempdir().unwrap();
    let ssh = fake::Server::start();
    let spare = fake::Server::start();
    let address = format!("127.0.0.1:{},ssh={}", daemon.port, ssh.port);
    let other = format!("127.0.0.1:{},ssh={}", daemon.port, spare.port);
    let mut client = spawn_qsh(
        &[
            "--authorize-ssh",
            "-i",
            key.to_str().unwrap(),
            &address,
            &other,
        ],
        home.path(),
    );
    let output = screen(&client);
    wait(&output, "Key fingerprint");
    client.master.write_all(b"yes\n").unwrap();
    wait(&output, "The authenticity of host");
    client.master.write_all(b"yes\n").unwrap();
    wait(&output, "Authorize SSH recovery");
    let shown = text(&output);
    assert!(shown.contains("QSH server"));
    assert!(shown.contains("SSH host"));
    assert!(shown.contains(&format!("127.0.0.1:{}", ssh.port)));
    let peer_key = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert!(shown.contains(&sshauth::known_hosts::key_fingerprint(&peer_key)));
    use base64::Engine as _;
    use sha2::Digest as _;
    let host_fingerprint = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(ssh.wire()))
    );
    assert!(shown.contains(&host_fingerprint));
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
    if store_error {
        // Create a concrete publication failure after the prompt has read an empty store.
        std::fs::create_dir(home.path().join("qsh/ssh_bindings.json")).unwrap();
    }
    client.master.write_all(answer).unwrap();
    wait(
        &output,
        &format!("The authenticity of host '[127.0.0.1]:{}'", spare.port),
    );
    client.master.write_all(b"no\n").unwrap();
    live(&mut client, &output);
    ssh.untouched();
    spare.untouched();
    if store_error {
        assert!(text(&output).contains("QSH session remains connected"));
        return;
    }
    let store = qsh::ssh_bindings::SshBindings::open(home.path().join("qsh/ssh_bindings.json"));
    let qshkey = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    let identity = connect::server_identity::ServerIdentity {
        qsh_key: qshkey,
        username: std::env::var("USER").unwrap(),
    };
    let endpoint = connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: ssh.port,
    };
    assert_eq!(
        store.allowed(&identity, &endpoint).unwrap(),
        if accept { vec![ssh.wire()] } else { vec![] }
    );
    assert!(store
        .allowed(
            &identity,
            &connect::server_identity::SshEndpoint {
                port: spare.port,
                ..endpoint
            }
        )
        .unwrap()
        .is_empty());
}

#[test]
fn cancelled_storage_write_waiting_for_lock_never_publishes_trust() {
    use connect::{
        recovery_gate::RecoveryEpoch,
        server_identity::{ServerIdentity, SshBinding, SshEndpoint},
    };
    use std::os::fd::AsRawFd;
    let home = tempfile::tempdir().unwrap();
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(home.path().join(".ssh_bindings.json.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let path = home.path().join("ssh_bindings.json");
    let target = path.clone();
    let cancel = knock::Cancel::new();
    let worker_cancel = cancel.clone();
    let permit = qsh::ssh_bindings::TrustWritePermit::new(RecoveryEpoch {
        connection: 1,
        network: 1,
    });
    let host = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let binding = SshBinding {
        server: ServerIdentity {
            qsh_key: [7; 32],
            username: "fixture".into(),
        },
        endpoint: SshEndpoint {
            host: "localhost".into(),
            port: 22,
        },
        host_key: host.public_key().to_bytes().unwrap(),
    };
    let worker = std::thread::spawn(move || {
        qsh::ssh_bindings::SshBindings::open(target).grant_cancellable(
            &binding,
            &permit,
            &worker_cancel,
        )
    });
    #[cfg(target_os = "linux")]
    {
        // Observe the writer's own lock fd, proving it passed its first
        // cancellation check and is blocked on the lock held above.
        let lock_path = home.path().join(".ssh_bindings.json.lock");
        assert!(wait_until(|| {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter(|fd| std::fs::read_link(fd.path()).ok().as_ref() == Some(&lock_path))
                .count()
                >= 2
        }));
    }
    cancel.cancel();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(matches!(
        worker.join().unwrap(),
        Err(qsh::ssh_bindings::BindingError::Cancelled)
    ));
    assert!(!path.exists());
}

#[path = "../../crates/bringup/tests/support_home/mod.rs"]
mod support_home;
#[test]
fn initial_bootstrap_binds_its_checked_key_only_after_qsh_validation() {
    bootstrap(b"yes\n", true);
}
#[test]
fn initial_bootstrap_binding_decline_preserves_the_live_shell() {
    bootstrap(b"no\n", false);
}
#[test]
fn cancelling_initial_bootstrap_consent_writes_no_binding() {
    bootstrap(b"\x03", false);
}
fn bootstrap(answer: &[u8], accept: bool) {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let identity = home.path().join("identity");
    std::fs::write(
        &identity,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let sb = support_home::Sandbox::start_with(&[key.public_key().to_openssh().unwrap()]);
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let port = free_udp_port();
    let address = format!("127.0.0.1:{port},ssh={}", sb.sshd.port);
    let mut client = spawn_qsh(&["-i", identity.to_str().unwrap(), &address], home.path());
    let output = screen(&client);
    wait(&output, "The authenticity of host");
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
    client.master.write_all(b"yes\n").unwrap();
    wait(&output, "Authorize SSH recovery");
    assert!(
        !text(&output).contains("Key fingerprint"),
        "{}",
        text(&output)
    );
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
    client.master.write_all(answer).unwrap();
    if answer == b"\x03" {
        assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(130));
        assert!(!home.path().join("qsh/ssh_bindings.json").exists());
        return;
    }
    live(&mut client, &output);
    let qsh_key = sshauth::discover::discover(
        ([127, 0, 0, 1], port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    let server = connect::server_identity::ServerIdentity {
        qsh_key,
        username: std::env::var("USER").unwrap(),
    };
    let endpoint = connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: sb.sshd.port,
    };
    let expected = support_home::ssh_support::wire_of(&sb.sshd.host_public_key_line());
    let allowed = qsh::ssh_bindings::SshBindings::open(home.path().join("qsh/ssh_bindings.json"))
        .allowed(&server, &endpoint)
        .unwrap();
    assert_eq!(allowed, if accept { vec![expected] } else { vec![] });
}

#[test]
fn corrupt_binding_store_during_explicit_setup_preserves_live_qsh() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let home = tempfile::tempdir().unwrap();
    let ssh = fake::Server::start();
    std::fs::create_dir_all(home.path().join("qsh")).unwrap();
    std::fs::write(home.path().join("qsh/ssh_bindings.json"), b"invalid-json").unwrap();
    qsh::known_hosts::KnownHosts::new(home.path().join(".ssh/known_hosts"), None)
        .add("127.0.0.1", ssh.port, "ssh-ed25519", &ssh.wire())
        .unwrap();
    let address = format!("127.0.0.1:{},ssh={}", daemon.port, ssh.port);
    let mut client = spawn_qsh(
        &["--authorize-ssh", "-i", key.to_str().unwrap(), &address],
        home.path(),
    );
    let output = screen(&client);
    wait(&output, "Key fingerprint");
    client.master.write_all(b"yes\n").unwrap();
    wait(&output, "invalid SSH binding store");
    live(&mut client, &output);
    ssh.untouched();
    assert!(text(&output).contains("QSH session remains connected"));
    assert_eq!(
        std::fs::read(home.path().join("qsh/ssh_bindings.json")).unwrap(),
        b"invalid-json"
    );
}
