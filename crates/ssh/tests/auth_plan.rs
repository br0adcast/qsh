mod support;

use std::sync::Arc;
use support::*;

fn go(params: ssh::SshParams, plan: ssh::SshAuthPlan) -> Result<(), ssh::SshError> {
    ssh::connect(
        params,
        plan,
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(c, _)| c.close())
}

fn plan(methods: Vec<ssh::AuthMethod>) -> ssh::SshAuthPlan {
    ssh::SshAuthPlan {
        methods,
        prompter: Arc::new(ssh::NoPrompts),
    }
}

/// A refused key is not the end: the next method runs in the same
/// connection, the way OpenSSH walks its identities.
#[test]
fn a_refused_key_then_an_accepted_one_log_in() {
    let Some(()) = sshd_or_skip() else { return };
    let good = SoftSigner::random();
    let sshd = TestSshd::start(&[good.authorized_line()]);
    let known = wire_of(&sshd.host_public_key_line());
    go(
        params(&sshd, vec![known]),
        plan(vec![
            ssh::AuthMethod::Signer(Arc::new(SoftSigner::random())),
            ssh::AuthMethod::Signer(Arc::new(good)),
        ]),
    )
    .expect("the second key logs in");
    // One connection, two offers: sshd logged both in the same session.
    let log = sshd.log();
    assert_eq!(log.matches("Accepted publickey").count(), 1, "{log}");
}

/// Every method refused: the error names what was tried.
#[test]
fn a_refused_plan_says_what_it_tried() {
    let Some(()) = sshd_or_skip() else { return };
    let sshd = TestSshd::start(&[SoftSigner::random().authorized_line()]);
    let known = wire_of(&sshd.host_public_key_line());
    match go(
        params(&sshd, vec![known]),
        plan(vec![
            ssh::AuthMethod::Signer(Arc::new(SoftSigner::random())),
            ssh::AuthMethod::Signer(Arc::new(SoftSigner::random())),
        ]),
    ) {
        Err(ssh::SshError::AuthFailed(reason)) => {
            assert!(reason.contains("publickey x2"), "{reason}")
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// More keys than MaxAuthTries: sshd ends the login with its own
/// SSH_MSG_DISCONNECT. That is a refused login a person can read -- the
/// server's words -- not a lost connection, a protocol error or a hang.
#[test]
fn too_many_keys_for_max_auth_tries_is_a_readable_refusal() {
    let Some(()) = sshd_or_skip() else { return };
    let good = SoftSigner::random();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![good.authorized_line()],
        max_auth_tries: Some(2),
        ..SshdOptions::default()
    });
    let known = wire_of(&sshd.host_public_key_line());
    let mut methods: Vec<ssh::AuthMethod> = (0..4)
        .map(|_| ssh::AuthMethod::Signer(Arc::new(SoftSigner::random())) as ssh::AuthMethod)
        .collect();
    methods.push(ssh::AuthMethod::Signer(Arc::new(good)));
    let started = std::time::Instant::now();
    match go(params(&sshd, vec![known]), plan(methods)) {
        Err(ssh::SshError::AuthFailed(reason)) => {
            assert!(reason.contains("the server ended the login"), "{reason}");
            assert!(
                reason.contains("Too many authentication failures"),
                "{reason}"
            );
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// The key named first is offered first: with MaxAuthTries 1 only the
/// first offer counts.
#[test]
fn the_first_method_is_offered_first() {
    let Some(()) = sshd_or_skip() else { return };
    let good = SoftSigner::random();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![good.authorized_line()],
        max_auth_tries: Some(1),
        ..SshdOptions::default()
    });
    let known = wire_of(&sshd.host_public_key_line());
    go(
        params(&sshd, vec![known]),
        plan(vec![
            ssh::AuthMethod::Signer(Arc::new(good)),
            ssh::AuthMethod::Signer(Arc::new(SoftSigner::random())),
        ]),
    )
    .expect("the first key logs in");
}

/// Nothing a person could not answer is ever printed.
#[test]
fn debug_never_prints_a_secret() {
    let p = ssh::AuthMethod::Password(ssh::Zeroizing::new("hunter2".into()));
    let k = ssh::AuthMethod::PrivateKeyPem(ssh::Zeroizing::new("-----BEGIN".into()));
    let text = format!("{p:?} {k:?}");
    assert!(
        !text.contains("hunter2") && !text.contains("BEGIN"),
        "{text}"
    );
}

fn plan_with(methods: Vec<ssh::AuthMethod>, prompter: Arc<CountingPrompter>) -> ssh::SshAuthPlan {
    ssh::SshAuthPlan { methods, prompter }
}

#[test]
fn an_agent_key_logs_in() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (path, pub_line) = keygen_file("ed25519", keys.path());
    let sshd = TestSshd::start(&[pub_line]);
    let agent = TestAgent::start();
    agent.add(&path);
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan(vec![ssh::AuthMethod::Agent(agent.socket())]),
    )
    .expect("the agent's key logs in");
}

#[test]
fn a_missing_agent_is_skipped_and_the_next_method_runs() {
    let Some(()) = sshd_or_skip() else { return };
    let good = SoftSigner::random();
    let sshd = TestSshd::start(&[good.authorized_line()]);
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan(vec![
            ssh::AuthMethod::Agent("/nonexistent/agent.sock".into()),
            ssh::AuthMethod::Signer(Arc::new(good)),
        ]),
    )
    .expect("the signer logs in after the missing agent");
}

/// The agent holds more keys than MaxAuthTries allows, and none is the
/// right one: a readable refusal, no hang.
#[test]
fn an_agent_with_too_many_wrong_keys_is_a_readable_refusal() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![SoftSigner::random().authorized_line()],
        max_auth_tries: Some(2),
        ..SshdOptions::default()
    });
    let agent = TestAgent::start();
    for kind in ["ed25519", "ecdsa", "rsa"] {
        agent.add(&keygen_file(kind, keys.path()).0);
    }
    let started = std::time::Instant::now();
    match go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan(vec![ssh::AuthMethod::Agent(agent.socket())]),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => {
            assert!(r.contains("the server ended the login"), "{r}");
            assert!(r.contains("Too many authentication failures"), "{r}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn an_unencrypted_key_file_logs_in_without_a_question() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (path, pub_line) = keygen_file("ed25519", keys.path());
    let sshd = TestSshd::start(&[pub_line]);
    let prompter = Arc::new(CountingPrompter::default());
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan_with(vec![ssh::AuthMethod::KeyFile(path)], Arc::clone(&prompter)),
    )
    .expect("login");
    assert_eq!(prompter.passphrase_asked(), 0);
}

#[test]
fn an_encrypted_key_asks_its_passphrase_once_and_logs_in() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (path, pub_line) = keygen_with_passphrase("ed25519", keys.path(), "correct horse");
    let sshd = TestSshd::start(&[pub_line]);
    let prompter = Arc::new(CountingPrompter::answering_passphrases(&["correct horse"]));
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan_with(vec![ssh::AuthMethod::KeyFile(path)], Arc::clone(&prompter)),
    )
    .expect("login");
    assert_eq!(prompter.passphrase_asked(), 1);
}

/// The server would not take this key anyway: nobody is asked for its passphrase.
#[test]
fn an_encrypted_key_the_server_refuses_asks_nothing() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (path, _) = keygen_with_passphrase("ed25519", keys.path(), "pw");
    let good = SoftSigner::random();
    let sshd = TestSshd::start(&[good.authorized_line()]);
    let prompter = Arc::new(CountingPrompter::answering_passphrases(&["pw"]));
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan_with(
            vec![
                ssh::AuthMethod::KeyFile(path),
                ssh::AuthMethod::Signer(Arc::new(good)),
            ],
            Arc::clone(&prompter),
        ),
    )
    .expect("the signer logs in");
    assert_eq!(prompter.passphrase_asked(), 0);
}

/// Declined, then three wrong answers on a second key: the plan goes on to
/// the next method in the same connection.
#[test]
fn a_declined_or_wrong_passphrase_moves_on_to_the_next_method() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (a, a_pub) = keygen_with_passphrase("ed25519", keys.path(), "a");
    let (b, b_pub) = keygen_with_passphrase("ecdsa", keys.path(), "b");
    let good = SoftSigner::random();
    let sshd = TestSshd::start(&[a_pub, b_pub, good.authorized_line()]);
    let prompter = Arc::new(CountingPrompter::answering_passphrases_opt(&[
        None,
        Some("x"),
        Some("y"),
        Some("z"),
    ]));
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan_with(
            vec![
                ssh::AuthMethod::KeyFile(a),
                ssh::AuthMethod::KeyFile(b),
                ssh::AuthMethod::Signer(Arc::new(good)),
            ],
            Arc::clone(&prompter),
        ),
    )
    .expect("the signer logs in");
    assert_eq!(prompter.passphrase_asked(), 4);
    // Both locked keys were taken by the server (PK_OK), their empty
    // signatures refused, and the login went on: one session, one success.
    let log = sshd.log();
    assert_eq!(log.matches("Failed publickey").count(), 2, "{log}");
    assert_eq!(log.matches("Accepted publickey").count(), 1, "{log}");
}

/// A key in the agent and the same key as a file: offered once.
#[test]
fn the_same_key_in_the_agent_and_a_file_is_offered_once() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (path, _) = keygen_file("ed25519", keys.path());
    let good = SoftSigner::random();
    let sshd = TestSshd::start(&[good.authorized_line()]);
    let agent = TestAgent::start();
    agent.add(&path);
    match go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan(vec![
            ssh::AuthMethod::Agent(agent.socket()),
            ssh::AuthMethod::KeyFile(path),
        ]),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => assert!(r.contains("publickey x1"), "{r}"),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// A person slower than connect_timeout still logs in.
#[test]
fn a_slow_passphrase_does_not_time_the_login_out() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (path, pub_line) = keygen_with_passphrase("ed25519", keys.path(), "slow");
    let sshd = TestSshd::start(&[pub_line]);
    let mut p = params(&sshd, vec![wire_of(&sshd.host_public_key_line())]);
    p.connect_timeout = std::time::Duration::from_secs(1);
    let prompter = Arc::new(
        CountingPrompter::answering_passphrases(&["slow"])
            .with_delay(std::time::Duration::from_secs(2)),
    );
    go(p, plan_with(vec![ssh::AuthMethod::KeyFile(path)], prompter)).expect("login");
}

/// RSA keys sign with the SHA-2 hash the server accepts, whether the agent
/// signs or a locked file is decrypted here.
#[test]
fn rsa_keys_log_in_from_the_agent_and_from_a_locked_file() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (in_agent, agent_pub) = keygen_file("rsa", keys.path());
    let (locked, locked_pub) = keygen_with_passphrase("rsa", keys.path(), "pw");
    let sshd = TestSshd::start(&[agent_pub, locked_pub]);
    let agent = TestAgent::start();
    agent.add(&in_agent);
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan(vec![ssh::AuthMethod::Agent(agent.socket())]),
    )
    .expect("the agent's RSA key logs in");
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan_with(
            vec![ssh::AuthMethod::KeyFile(locked)],
            Arc::new(CountingPrompter::answering_passphrases(&["pw"])),
        ),
    )
    .expect("the locked RSA key logs in");
    let log = sshd.log();
    assert_eq!(log.matches("Accepted publickey").count(), 2, "{log}");
    assert_eq!(log.matches("pkalg rsa-sha2-").count(), 2, "{log}");
    assert!(!log.contains("pkalg ssh-rsa "), "SHA-1 RSA was used: {log}");
}

/// `AuthenticationMethods publickey,publickey`: the first key is a partial
/// success, the second finishes the login in the same connection; one key
/// alone is refused.
#[test]
fn a_server_wanting_two_keys_takes_two_and_refuses_one() {
    let Some(()) = sshd_or_skip() else { return };
    let (first, second) = (SoftSigner::random(), SoftSigner::random());
    let first_alone = SoftSigner(first.0.clone());
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![first.authorized_line(), second.authorized_line()],
        authentication_methods: Some("publickey,publickey"),
        ..SshdOptions::default()
    });
    let known = wire_of(&sshd.host_public_key_line());
    go(
        params(&sshd, vec![known.clone()]),
        plan(vec![
            ssh::AuthMethod::Signer(Arc::new(first)),
            ssh::AuthMethod::Signer(Arc::new(second)),
        ]),
    )
    .expect("two keys log in");
    let log = sshd.log();
    assert!(log.contains("Partial publickey"), "{log}");
    // One of the two keys is only half a login.
    match go(
        params(&sshd, vec![known]),
        plan(vec![ssh::AuthMethod::Signer(Arc::new(first_alone))]),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => assert!(r.contains("publickey x1"), "{r}"),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[path = "../../sshauth/tests/support/key_formats.rs"]
mod key_formats;

#[test]
fn ordinary_pkcs8_key_files_authenticate_without_prompting() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let mut identities = Vec::new();
    let mut public = Vec::new();
    for (index, algorithm) in [
        ssh_key::Algorithm::Ed25519,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP384,
        },
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP521,
        },
        ssh_key::Algorithm::Rsa { hash: None },
    ]
    .into_iter()
    .enumerate()
    {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            algorithm,
        )
        .unwrap();
        public.push(key.public_key().to_openssh().unwrap());
        let path = keys.path().join(format!("identity-{index}"));
        russh::keys::encode_pkcs8_pem(&key, std::fs::File::create(&path).unwrap()).unwrap();
        identities.push(path);
    }
    let sshd = TestSshd::start(&public);
    for identity in identities {
        let prompter = Arc::new(CountingPrompter::default());
        go(
            params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
            plan_with(
                vec![ssh::AuthMethod::KeyFile(identity)],
                Arc::clone(&prompter),
            ),
        )
        .expect("the generated PKCS8 key must authenticate");
        assert_eq!(prompter.passphrase_asked(), 0);
    }
    assert_eq!(sshd.log().matches("Accepted publickey").count(), 5);
}

#[test]
fn explicit_parameter_sec1_file_retains_upstream_ssh_authentication() {
    use p256::elliptic_curve::Generate;
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let private = p256::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 {
            public: private.public_key().into(),
            private: private.clone().into(),
        }),
        "generated explicit parameters",
    )
    .unwrap();
    let named = keys.path().join("named");
    let explicit = keys.path().join("explicit");
    std::fs::write(
        &named,
        private
            .to_sec1_pem(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    key_formats::openssl(&named, &explicit, &["ec", "-param_enc", "explicit"]);
    let sshd = TestSshd::start(&[key.public_key().to_openssh().unwrap()]);
    let prompter = Arc::new(CountingPrompter::default());
    go(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        plan_with(
            vec![ssh::AuthMethod::KeyFile(explicit)],
            Arc::clone(&prompter),
        ),
    )
    .expect("the existing upstream explicit-parameter route must remain usable");
    assert_eq!(prompter.passphrase_asked(), 0);
    assert_eq!(sshd.log().matches("Accepted publickey").count(), 1);
}

#[test]
fn annotated_pkcs8_and_sec1_files_authenticate_without_prompting() {
    use p256::elliptic_curve::Generate;
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let private = p256::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 {
            public: private.public_key().into(),
            private: private.clone().into(),
        }),
        "generated annotated fixture",
    )
    .unwrap();
    let mut pkcs8 = Vec::new();
    russh::keys::encode_pkcs8_pem(&key, &mut pkcs8).unwrap();
    let sec1 = private.to_sec1_pem(ssh_key::LineEnding::LF).unwrap();
    let sshd = TestSshd::start(&[key.public_key().to_openssh().unwrap()]);
    for (index, encoded) in [pkcs8.as_slice(), sec1.as_bytes()].into_iter().enumerate() {
        let path = keys.path().join(format!("annotated-{index}"));
        let mut text = b"Bag Attributes\n    friendlyName: generated fixture\nKey Attributes: <No Attributes>\n".to_vec();
        text.extend_from_slice(encoded);
        std::fs::write(&path, &text).unwrap();
        let prompter = Arc::new(CountingPrompter::default());
        go(
            params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
            plan_with(vec![ssh::AuthMethod::KeyFile(path)], Arc::clone(&prompter)),
        )
        .expect("annotated ordinary files must preserve SSH authentication");
        assert_eq!(prompter.passphrase_asked(), 0);
    }
    assert_eq!(sshd.log().matches("Accepted publickey").count(), 2);
}
