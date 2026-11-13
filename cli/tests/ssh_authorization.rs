#[path = "support/recovery_ssh.rs"]
mod fake;
mod support;
#[path = "../../crates/bringup/tests/support_home/mod.rs"]
mod support_home;
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use support::*;
#[test]
fn removed_authorization_option_fails_before_network() {
    let args = ["--authorize-ssh", "alice@127.0.0.1,nossh"].map(String::from);
    let error = qsh::args::parse_args(&args).unwrap_err().to_string();
    assert!(error.contains("unknown option --authorize-ssh"), "{error}");
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
/// A first connection from a new machine: the daemon on `port` is pinned,
/// but neither this client's qsh key nor its SSH key (`-i`) is listed, so
/// the direct attempt is refused and the bootstrap logs in over `ssh`.
fn unlisted_client(port: u16, ssh: &fake::Server) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let peer_key = sshauth::discover::discover(
        ([127, 0, 0, 1], port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    sshauth::known_hosts::KnownHosts::open(home.path().join("qsh/known_hosts"))
        .pin("127.0.0.1", port, &peer_key)
        .unwrap();
    let ssh_dir = home.path().join(".ssh");
    std::fs::create_dir(&ssh_dir).unwrap();
    std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    qsh::known_hosts::KnownHosts::new(ssh_dir.join("known_hosts"), None)
        .add("127.0.0.1", ssh.port, "ssh-ed25519", &ssh.wire())
        .unwrap();
    let unlisted = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let identity = home.path().join("unlisted");
    support::write_private(
        &identity,
        unlisted
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    (home, identity)
}
fn spawn_unlisted(
    identity: &std::path::Path,
    port: u16,
    ssh: &fake::Server,
    home: &std::path::Path,
) -> Client {
    let address = format!("127.0.0.1:{port},ssh={}", ssh.port);
    spawn_qsh(
        &["--no-password", "-i", identity.to_str().unwrap(), &address],
        home,
    )
}
/// The remote side for `fake::Server::start_shell`: a private home with the
/// sshd sandbox's environment, and the qshd lookup path in its cache.
fn remote_home() -> (tempfile::TempDir, fake::Shell, std::path::PathBuf) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let home = tempfile::Builder::new()
        .prefix("qsh remote ' ")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(home.path().join(".cache/qsh"))
        .unwrap();
    std::fs::create_dir_all(home.path().join("bin")).unwrap();
    let mut env =
        support_home::ssh_support::shell_env::prepare(home.path(), std::path::Path::new("/bin/sh"));
    env.push((
        "PATH".into(),
        format!("{}/bin:/usr/bin:/bin", home.path().display()),
    ));
    let qshd = home.path().join(format!(
        ".cache/qsh/qshd-{}-{}",
        qshd::state::QSHD_VERSION,
        std::env::consts::ARCH
    ));
    let shell = fake::Shell {
        home: home.path().to_path_buf(),
        env,
    };
    (home, shell, qshd)
}
/// Each recorded command by its role in the bring-up. Commands arrive as
/// `/bin/sh -c '<script>'`; the scripts' own markers tell them apart.
fn steps(ssh: &fake::Server) -> Vec<&'static str> {
    ssh.commands()
        .iter()
        .map(|command| {
            if command.contains("; purpose=execute;") {
                "trust"
            } else if command.contains("systemctl is-active --quiet qshd.service") {
                "lookup"
            } else if command.contains(" server-info --challenge ") {
                "server-info"
            } else if command.contains(" bootstrap-capabilities") {
                "bootstrap-capabilities"
            } else if command.contains(" transport-ensure ") {
                "transport-ensure"
            } else {
                "other"
            }
        })
        .collect()
}
#[test]
fn unlisted_key_bootstrap_failure_stays_on_its_single_ssh_login() {
    use std::sync::atomic::Ordering;
    let _serial = serialised();
    let (daemon, _) = start_daemon();
    let ssh = fake::Server::start();
    let (home, identity) = unlisted_client(daemon.port, &ssh);
    let mut client = spawn_unlisted(&identity, daemon.port, &ssh, home.path());
    let screen = screen(&client);
    let status = wait_for_exit(&mut client.child).unwrap();
    assert!(!status.success(), "{}", text(&screen));
    // The fake reports no installed qshd, so the bring-up ends at its lookup.
    let activity = &ssh.activity;
    assert_eq!(
        activity.connections.load(Ordering::SeqCst),
        1,
        "{}",
        text(&screen)
    );
    assert_eq!(activity.sign.load(Ordering::SeqCst), 1);
    assert_eq!(steps(&ssh), ["lookup"]);
}
#[test]
fn unlisted_key_bootstrap_reads_server_info_then_starts_on_its_single_ssh_login() {
    use base64::Engine;
    use std::sync::atomic::Ordering;
    let _serial = serialised();
    let (remote, shell, qshd) = remote_home();
    std::fs::copy(support_home::qshd_path(), &qshd).unwrap();
    // Declared after `remote`, so it stops the daemon before the home goes.
    let _daemon =
        support_home::daemon_guard::DaemonGuard::new(remote.path().join(".cache/qsh/control.sock"));
    // The daemon that bootstrap will reuse, started as bring-up starts it,
    // for another client: this one's qsh key is not authorized yet.
    let port = free_udp_port();
    let started = std::process::Command::new(&qshd)
        .args([
            "transport-ensure",
            "--name",
            "console",
            "--port",
            &port.to_string(),
            "--client-pubkey",
        ])
        .arg(base64::engine::general_purpose::STANDARD.encode([7u8; 32]))
        .env_clear()
        .envs(shell.env.iter().cloned())
        .current_dir(remote.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(started.status.success(), "{started:?}");
    let answering = wait_until(|| {
        sshauth::discover::discover(
            ([127, 0, 0, 1], port).into(),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
    });
    assert!(answering, "the started daemon never answered discovery");
    let ssh = fake::Server::start_shell(shell);
    let (home, identity) = unlisted_client(port, &ssh);
    let mut client = spawn_unlisted(&identity, port, &ssh, home.path());
    let screen = screen(&client);
    live(&mut client, &screen);
    // One login, one signature, and every command on it in bring-up order:
    // server-info runs after the trust check and before transport-ensure.
    let activity = &ssh.activity;
    assert_eq!(
        activity.connections.load(Ordering::SeqCst),
        1,
        "{}",
        text(&screen)
    );
    assert_eq!(activity.sign.load(Ordering::SeqCst), 1);
    assert_eq!(
        steps(&ssh),
        ["lookup", "trust", "server-info", "transport-ensure"]
    );
    // The gate saw verified, compatible server info, not unknown metadata:
    // the reply binds this query's challenge and the pinned daemon key.
    let finished = activity.finished.lock().unwrap();
    let query = finished
        .iter()
        .find(|f| f.command.contains(" server-info --challenge "))
        .unwrap();
    let hex = &query
        .command
        .split(" server-info --challenge ")
        .nth(1)
        .unwrap()[..64];
    let challenge: [u8; 32] =
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
    let key = sshauth::discover::discover(
        ([127, 0, 0, 1], port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(query.code, 0);
    let info =
        ssh::server_info::verify(&query.stdout, &challenge, &key).expect("verified server info");
    assert_eq!(
        qsh::server_discovery::decision(Some(info.info())).compatibility,
        connect::upgrade::Compatibility::Compatible
    );
}
#[test]
fn verified_incompatible_server_info_stops_the_bootstrap_before_any_change() {
    use std::sync::atomic::Ordering;
    let _serial = serialised();
    // The pinned daemon the client is refused by; its key binds the reply.
    let (daemon, _) = start_daemon();
    let peer_key = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    let key: String = peer_key.iter().map(|b| format!("{b:02x}")).collect();
    let (remote, shell, qshd) = remote_home();
    // The located qshd answers server-info for the pinned key with a session
    // profile this client lacks, and records anything else it is asked to do.
    executable_script(&qshd, &format!(
        "case \"$1\" in\n\
         server-info) printf '{{\"challenge\":\"%s\",\"server_pubkey\":\"{key}\",\"generation\":\"{gen}\",\"core_version\":\"9.0.0\",\"session_protocols\":[[1,1,1]]}}' \"$3\" ;;\n\
         *) printf '%s\\n' \"$*\" >> \"$HOME/forbidden\"; exit 1 ;;\n\
         esac",
        gen = "00".repeat(16)
    ));
    let ssh = fake::Server::start_shell(shell);
    let (home, identity) = unlisted_client(daemon.port, &ssh);
    let mut client = spawn_unlisted(&identity, daemon.port, &ssh, home.path());
    let screen = screen(&client);
    let status = wait_for_exit(&mut client.child).unwrap();
    assert!(!status.success(), "{}", text(&screen));
    // The client authenticated the reply and reports the incompatibility.
    assert!(
        text(&screen)
            .contains("authenticated qshd 9.0.0 does not support this client's session profile"),
        "{}",
        text(&screen)
    );
    // One login and signature, and nothing after server-info: no approval,
    // upload, installation, capability check or transport-ensure.
    let activity = &ssh.activity;
    assert_eq!(
        activity.connections.load(Ordering::SeqCst),
        1,
        "{}",
        text(&screen)
    );
    assert_eq!(activity.sign.load(Ordering::SeqCst), 1);
    assert_eq!(steps(&ssh), ["lookup", "trust", "server-info"]);
    assert!(!remote.path().join("forbidden").exists());
    let cached: Vec<_> = std::fs::read_dir(remote.path().join(".cache/qsh"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(cached, [qshd]);
    // The refusing daemon itself is untouched and still answering.
    let still = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(still, peer_key);
}
fn executable_script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
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
fn ssh_first_initial_bootstrap_needs_no_association_question_or_store() {
    bootstrap();
}
fn bootstrap() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let identity = home.path().join("identity");
    support::write_private(
        &identity,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let sb = support_home::Sandbox::start_with(&[key.public_key().to_openssh().unwrap()]);
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let port = free_udp_port();
    let address = format!("127.0.0.1:{port},ssh={}", sb.sshd.port);
    let args = vec!["-i", identity.to_str().unwrap(), &address];
    let mut client = spawn_qsh(&args, home.path());
    let output = screen(&client);
    wait(&output, "The authenticity of host");
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
    client.master.write_all(b"yes\n").unwrap();
    live(&mut client, &output);
    let shown = text(&output);
    assert!(!shown.contains("Authorize SSH recovery"), "{shown}");
    assert!(!shown.contains("Key fingerprint"), "{shown}");
    assert!(!home.path().join("qsh/ssh_bindings.json").exists());
}
