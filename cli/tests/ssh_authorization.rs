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
    std::fs::write(
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
