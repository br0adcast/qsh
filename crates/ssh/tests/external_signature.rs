mod support;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use support::*;

// A real signer with independently encoded SSH output. The SSH layer must
// consume this blob directly, without assuming a platform DER representation.
struct WireSigner {
    key: SoftSigner,
    corrupt: u8,
}

impl ssh::ExternalSigner for WireSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.key.public_wire())
    }

    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.key.0.sign(data);
        let signature =
            ssh_key::Signature::try_from(&signature).map_err(|error| error.to_string())?;
        let mut blob =
            sshauth::record::encode_signature(&signature).map_err(|error| error.to_string())?;
        match self.corrupt {
            1 => blob = b"invalid signature".to_vec(),
            2 => blob.push(0),
            _ => {}
        }
        Ok(blob)
    }
}

fn login(corrupt: u8) -> Result<(), ssh::SshError> {
    let key = SoftSigner::random();
    let sshd = TestSshd::start(&[key.authorized_line()]);
    ssh::connect(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(WireSigner {
            key,
            corrupt,
        }))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(connection, _)| connection.close())
}

#[test]
fn an_external_ssh_signature_authenticates() {
    let Some(()) = sshd_or_skip() else { return };
    login(0).expect("a standard SSH signature authenticates");
}

#[test]
fn malformed_external_signatures_fail_without_waiting_for_the_server() {
    let Some(()) = sshd_or_skip() else { return };
    for corrupt in [1, 2] {
        let start = Instant::now();
        let result = login(corrupt);
        assert!(
            matches!(result, Err(ssh::SshError::AuthFailed(_))),
            "{result:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "invalid signer output must fail promptly"
        );
    }
}

use sshauth::prepared_key::{PreparedKey, RsaDigest};
use support::fake_server::{FakeAuth, FakeServer, ServerActivity};

fn prepared(algorithm: ssh_key::Algorithm) -> Arc<PreparedKey> {
    Arc::new(
        PreparedKey::from_key(
            ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                algorithm,
            )
            .unwrap(),
        )
        .unwrap(),
    )
}
fn rsa() -> Arc<PreparedKey> {
    static KEY: OnceLock<Arc<PreparedKey>> = OnceLock::new();
    KEY.get_or_init(|| prepared(ssh_key::Algorithm::Rsa { hash: None }))
        .clone()
}
fn encoded(key: &PreparedKey, data: &[u8], digest: RsaDigest) -> Result<Vec<u8>, String> {
    let signature = key.sign(data, digest).map_err(|e| e.to_string())?;
    sshauth::record::encode_signature(&signature).map_err(|e| e.to_string())
}

struct LegacySigner(Arc<PreparedKey>);
impl ssh::ExternalSigner for LegacySigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        self.0.public_key().to_bytes().map_err(|e| e.to_string())
    }
    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        encoded(&self.0, data, RsaDigest::Sha1)
    }
}

struct AlgorithmSigner {
    key: Arc<PreparedKey>,
    requested: Arc<Mutex<Option<String>>>,
    wrong_hash: bool,
}
impl ssh::ExternalSigner for AlgorithmSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        self.key.public_key().to_bytes().map_err(|e| e.to_string())
    }
    fn sign_ssh(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("this RSA provider requires an explicit algorithm".into())
    }
    fn sign_ssh_with_algorithm(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        let mut requested = self.requested.lock().unwrap();
        if requested.is_some() {
            return Err("duplicate signing request".into());
        }
        *requested = Some(algorithm.to_string());
        let mut digest = match algorithm {
            "ssh-rsa" => RsaDigest::Sha1,
            "rsa-sha2-256" => RsaDigest::Sha256,
            "rsa-sha2-512" => RsaDigest::Sha512,
            _ => return Err("unexpected signature algorithm".into()),
        };
        if self.wrong_hash {
            digest = if digest == RsaDigest::Sha256 {
                RsaDigest::Sha512
            } else {
                RsaDigest::Sha256
            };
        }
        encoded(&self.key, data, digest)
    }
}

fn fake_login(
    server: &FakeServer,
    signer: Arc<dyn ssh::ExternalSigner>,
) -> Result<(), ssh::SshError> {
    ssh::connect(
        ssh::SshParams {
            host: "127.0.0.1".into(),
            port: server.port,
            username: "generated".into(),
            known_host_keys: vec![server.host_public_key_wire()],
            connect_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(15),
            compression: false,
            tcp_nodelay: true,
            knock: vec![],
        },
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(signer)),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(connection, _)| connection.close())
}

#[test]
fn external_rsa_signer_uses_each_peer_selected_algorithm() {
    use russh::keys::HashAlg;
    use std::sync::atomic::Ordering;
    for (hash, expected) in [
        (None, "ssh-rsa"),
        (Some(HashAlg::Sha256), "rsa-sha2-256"),
        (Some(HashAlg::Sha512), "rsa-sha2-512"),
    ] {
        let activity = Arc::new(ServerActivity::default());
        let server = FakeServer::start(FakeAuth {
            accept_any_key: true,
            rsa_hash: Some(hash),
            activity: activity.clone(),
            ..Default::default()
        });
        let requested = Arc::new(Mutex::new(None));
        fake_login(
            &server,
            Arc::new(AlgorithmSigner {
                key: rsa(),
                requested: requested.clone(),
                wrong_hash: false,
            }),
        )
        .unwrap();
        assert_eq!(requested.lock().unwrap().as_deref(), Some(expected));
        assert_eq!(activity.signed_publickey.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn wrong_external_rsa_hash_never_reaches_signed_peer_authentication() {
    use russh::keys::HashAlg;
    use std::sync::atomic::Ordering;
    let activity = Arc::new(ServerActivity::default());
    let server = FakeServer::start(FakeAuth {
        accept_any_key: true,
        rsa_hash: Some(Some(HashAlg::Sha512)),
        activity: activity.clone(),
        ..Default::default()
    });
    let requested = Arc::new(Mutex::new(None));
    let result = fake_login(
        &server,
        Arc::new(AlgorithmSigner {
            key: rsa(),
            requested: requested.clone(),
            wrong_hash: true,
        }),
    );
    assert!(
        matches!(result, Err(ssh::SshError::AuthFailed(_))),
        "{result:?}"
    );
    assert_eq!(requested.lock().unwrap().as_deref(), Some("rsa-sha2-512"));
    assert_eq!(activity.signed_publickey.load(Ordering::SeqCst), 0);
}

#[test]
fn existing_fixed_algorithm_external_signers_remain_compatible() {
    use ssh_key::{Algorithm, EcdsaCurve};
    for key in [
        prepared(Algorithm::Ed25519),
        prepared(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }),
        rsa(),
    ] {
        let server = FakeServer::start(FakeAuth {
            accept_any_key: true,
            rsa_hash: Some(None),
            ..Default::default()
        });
        fake_login(&server, Arc::new(LegacySigner(key))).unwrap();
    }
}
