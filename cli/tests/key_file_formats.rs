//! A supported ordinary identity must reach a real QSH shell through the CLI.
mod support;

use std::sync::{Arc, Mutex};
use support::*;

#[test]
fn a_pkcs8_identity_reaches_the_authenticated_qsh_shell() {
    let _serial = serialised();
    let (daemon, openssh) = start_daemon();
    let home = tempfile::tempdir().unwrap();
    let key = ssh_key::PrivateKey::read_openssh_file(&openssh).unwrap();
    let identity = home.path().join("identity-pkcs8");
    russh::keys::encode_pkcs8_pem(&key, std::fs::File::create(&identity).unwrap()).unwrap();
    let host_key = sshauth::discover::discover(
        ([127, 0, 0, 1], daemon.port).into(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    sshauth::known_hosts::KnownHosts::open(home.path().join("qsh/known_hosts"))
        .pin("127.0.0.1", daemon.port, &host_key)
        .unwrap();
    let address = format!("127.0.0.1:{},nossh", daemon.port);
    let mut client = spawn_qsh(&["-i", identity.to_str().unwrap(), &address], home.path());
    let output = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), Arc::clone(&output));
    client.type_line("printf '%s\\n' FORMAT_'IDENTITY_ACCEPTED'");
    assert!(
        wait_until(|| {
            let bytes = output.lock().unwrap();
            String::from_utf8_lossy(&bytes).contains("FORMAT_IDENTITY_ACCEPTED")
        }),
        "the authenticated shell must execute the command, not merely echo its input"
    );
    assert!(!String::from_utf8_lossy(&output.lock().unwrap()).contains("Passphrase for key"));
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}
