mod support;

use std::sync::Arc;
use support::*;

fn login(params: ssh::SshParams, signer: SoftSigner) -> Result<(), ssh::SshError> {
    ssh::connect(
        params,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(c, _)| c.close())
}

/// The server has ed25519 and ecdsa host keys and would pick ed25519 by
/// default. Only the ecdsa one is known: offering its type first makes the
/// server show the key we know, instead of a "changed" key that is not.
#[test]
fn a_known_key_of_a_second_type_is_trusted() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![signer.authorized_line()],
        host_key_types: vec!["ed25519", "ecdsa"],
        ..SshdOptions::default()
    });
    let ecdsa = wire_of(&sshd.host_public_key_line_of("ecdsa"));
    login(params(&sshd, vec![ecdsa]), signer).expect("the known ecdsa key is trusted");
}

/// Two known keys for one host: either one matches.
#[test]
fn any_of_several_known_keys_is_trusted() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let host = wire_of(&sshd.host_public_key_line());
    let stranger = SoftSigner::random().public_wire();
    login(params(&sshd, vec![stranger, host]), signer).expect("login");
}

/// An RSA host key is known: it is asked for with SHA-2, and trusted.
#[test]
fn a_known_rsa_host_key_is_trusted() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![signer.authorized_line()],
        host_key_types: vec!["ed25519", "rsa"],
        ..SshdOptions::default()
    });
    let rsa = wire_of(&sshd.host_public_key_line_of("rsa"));
    login(params(&sshd, vec![rsa]), signer).expect("the known rsa key is trusted");
}

/// No known key: unknown, never changed.
#[test]
fn no_known_key_is_unknown() {
    let Some(()) = sshd_or_skip() else { return };
    let sshd = TestSshd::start(&[]);
    match login(params(&sshd, vec![]), SoftSigner::random()) {
        Err(ssh::SshError::UnknownHostKey(_)) => {}
        other => panic!("expected UnknownHostKey, got {other:?}"),
    }
}
