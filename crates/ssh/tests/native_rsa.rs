//! Real authenticated connections using the shared native private-key route.
mod support;
use std::sync::Arc;
use support::{
    fake_server::{FakeAuth, FakeServer},
    CountingPrompter, NullEvents,
};

fn connect(
    server: &FakeServer,
    method: ssh::AuthMethod,
    prompter: Arc<CountingPrompter>,
) -> Result<(), ssh::SshError> {
    ssh::connect(
        ssh::SshParams {
            host: "127.0.0.1".into(),
            port: server.port,
            username: "generated".into(),
            known_host_keys: vec![server.host_public_key_wire()],
            connect_timeout: std::time::Duration::from_secs(5),
            keepalive_interval: std::time::Duration::from_secs(15),
            compression: false,
            tcp_nodelay: true,
            knock: Vec::new(),
        },
        ssh::SshAuthPlan {
            methods: vec![method],
            prompter,
        },
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(connection, _)| connection.close())
}

#[test]
fn local_rsa_files_and_pem_connect_with_each_advertised_ssh_digest() {
    use russh::keys::HashAlg;
    let dir = tempfile::tempdir().unwrap();
    let (plain, _) = support::keygen_file("rsa", dir.path());
    let (locked, _) = support::keygen_with_passphrase("rsa", dir.path(), "generated passphrase");
    for hash in [None, Some(HashAlg::Sha256), Some(HashAlg::Sha512)] {
        let server = FakeServer::start(FakeAuth {
            accept_any_key: true,
            rsa_hash: Some(hash),
            ..Default::default()
        });
        connect(
            &server,
            ssh::AuthMethod::KeyFile(plain.clone()),
            Arc::new(CountingPrompter::default()),
        )
        .unwrap();
        let pem = zeroize::Zeroizing::new(std::fs::read_to_string(&plain).unwrap());
        connect(
            &server,
            ssh::AuthMethod::PrivateKeyPem(pem),
            Arc::new(CountingPrompter::default()),
        )
        .unwrap();
        let prompts = Arc::new(CountingPrompter::answering_passphrases(&[
            "wrong",
            "generated passphrase",
        ]));
        connect(
            &server,
            ssh::AuthMethod::KeyFile(locked.clone()),
            prompts.clone(),
        )
        .unwrap();
        assert_eq!(prompts.passphrase_asked(), 2);
    }
}

#[test]
fn a_refused_native_rsa_identity_does_not_prompt_for_its_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (locked, _) = support::keygen_with_passphrase("rsa", dir.path(), "generated passphrase");
    let server = FakeServer::start(FakeAuth {
        rsa_hash: Some(None),
        ..Default::default()
    });
    let prompts = Arc::new(CountingPrompter::answering_passphrases(&[
        "generated passphrase",
    ]));
    assert!(matches!(
        connect(&server, ssh::AuthMethod::KeyFile(locked), prompts.clone()),
        Err(ssh::SshError::AuthFailed(_))
    ));
    assert_eq!(prompts.passphrase_asked(), 0);
}

fn malformed_rsa_file(dir: &std::path::Path, locked: bool) -> (std::path::PathBuf, String) {
    use ssh_key::{
        private::{KeypairData, RsaKeypair, RsaPrivateKey},
        Mpint, PrivateKey,
    };
    let pair = RsaKeypair::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        2048,
    )
    .unwrap();
    let private = RsaPrivateKey::new(
        Mpint::from_positive_bytes(&[3]),
        pair.private().iqmp().clone(),
        pair.private().p().clone(),
        pair.private().q().clone(),
    )
    .unwrap();
    let key = PrivateKey::new(
        KeypairData::Rsa(RsaKeypair::new(pair.public().clone(), private).unwrap()),
        "generated invalid private exponent",
    )
    .unwrap();
    let public = key.public_key().to_openssh().unwrap();
    assert!(sshauth::prepared_key::PreparedKey::from_key(key.clone()).is_err());
    let key = if locked {
        key.encrypt(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            "generated passphrase",
        )
        .unwrap()
    } else {
        key
    };
    let path = dir.join("malformed-rsa");
    std::fs::write(
        &path,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    (path, public)
}

fn malformed_attempt(locked: bool) -> (Result<(), ssh::SshError>, usize, String) {
    let dir = tempfile::tempdir().unwrap();
    let (bad, bad_public) = malformed_rsa_file(dir.path(), locked);
    let (good, good_public) = support::keygen_file("ed25519", dir.path());
    let server = support::TestSshd::start(&[bad_public, good_public]);
    let prompter = Arc::new(CountingPrompter::answering_passphrases(&[
        "generated passphrase",
    ]));
    let result = ssh::connect(
        support::params(
            &server,
            vec![support::wire_of(&server.host_public_key_line())],
        ),
        ssh::SshAuthPlan {
            methods: vec![
                ssh::AuthMethod::KeyFile(bad),
                ssh::AuthMethod::KeyFile(good),
            ],
            prompter: prompter.clone(),
        },
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(connection, _)| connection.close());
    (result, prompter.passphrase_asked(), server.log())
}

#[test]
fn native_rsa_failure_before_offer_preserves_configured_discovery() {
    let Some(()) = support::sshd_or_skip() else {
        return;
    };
    let (result, prompts, log) = malformed_attempt(false);
    result.expect("initial unreadable identity preserves the configured candidate plan");
    assert_eq!(prompts, 0);
    assert_eq!(log.matches("Accepted publickey").count(), 1);
}

#[test]
fn native_rsa_failure_after_publickey_acceptance_never_changes_identity() {
    let Some(()) = support::sshd_or_skip() else {
        return;
    };
    let (result, prompts, log) = malformed_attempt(true);
    assert_eq!(prompts, 1, "PK_OK must precede decrypt/native validation");
    assert!(
        matches!(result, Err(ssh::SshError::AuthFailed(ref why)) if why.contains("native private-key operation failed")),
        "accepted identity's native failure must end authentication, got {result:?}"
    );
    assert_eq!(
        log.matches("Accepted publickey").count(),
        0,
        "the configured alternate identity must not be used"
    );
}
