//! Signing with a private key read from disk -- the fallback for when there
//! is no agent.

use std::path::Path;

use ssh_key::{PrivateKey, PublicKey};
use transport::auth::{record_challenge, AuthError, AuthRecord, AuthSigner, AUTH_NONCE_LEN};

use crate::record::{encode_public_key, encode_signature};

/// Signs with one private key held in memory.
pub struct FileSigner {
    key: crate::prepared_key::PreparedKey,
    login: Option<String>,
    #[cfg(test)]
    native_probe: Option<std::sync::Arc<NativeProbe>>,
}

impl FileSigner {
    /// Read a private key. An encrypted key needs its passphrase; without one
    /// the load fails rather than prompting -- asking the user is the caller's
    /// job, since only it knows whether a terminal is even attached.
    pub fn load(path: &Path, passphrase: Option<&str>) -> Result<FileSigner, AuthError> {
        Self::load_classified(path, passphrase)
            .map_err(|e| AuthError::Backend(format!("reading {}: {e}", path.display())))
    }

    /// Load a file while retaining the distinction between a locked OpenSSH
    /// key and failures for which asking a passphrase cannot help.
    pub fn load_classified(
        path: &Path,
        passphrase: Option<&str>,
    ) -> Result<FileSigner, crate::keyfile::KeyFileError> {
        let key = crate::keyfile::read(path)?.into_prepared(passphrase)?;
        Ok(Self::from_prepared(key))
    }

    /// Build a signer around a key already in hand. The loader above is the
    /// usual way in; this one exists for callers that decrypted the key
    /// themselves, and for tests.
    pub fn from_key(key: PrivateKey) -> Result<FileSigner, crate::keyfile::KeyFileError> {
        let key = crate::prepared_key::PreparedKey::from_key(key)?;
        Ok(Self::from_prepared(key))
    }

    /// Build a signer from an already prepared owner without rereading a file
    /// or validating private factors again.
    pub fn from_prepared(key: crate::prepared_key::PreparedKey) -> FileSigner {
        FileSigner {
            key,
            login: None,
            #[cfg(test)]
            native_probe: None,
        }
    }

    /// The login name this signer claims. Required before a version 2
    /// record can be made.
    pub fn with_login(mut self, login: String) -> Self {
        self.login = Some(login);
        self
    }

    /// The public half, for showing the user which key was offered.
    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }
}

impl AuthSigner for FileSigner {
    fn sign(
        &self,
        handshake_hash: &[u8; 32],
        nonce: Option<&[u8; AUTH_NONCE_LEN]>,
    ) -> Result<AuthRecord, AuthError> {
        let v2 = crate::v2_fields(self.login.as_deref(), nonce)?;
        // The challenge depends on the version 2 fields, so the record is
        // assembled first and signed second.
        let mut record = AuthRecord {
            public_key: encode_public_key(self.key.public_key())?,
            signature: Vec::new(),
            v2,
        };
        let signature = self
            .key
            .sign_inner(
                &record_challenge(handshake_hash, &record),
                crate::prepared_key::RsaDigest::Sha512,
                #[cfg(test)]
                self.native_probe.as_deref(),
            )
            .map_err(|e| AuthError::Backend(format!("signing: {e}")))?;
        if !crate::verify::signature_algorithm_allowed(&signature.algorithm()) {
            return Err(AuthError::Backend(
                "the key produced a signature algorithm QSH does not accept".to_string(),
            ));
        }
        record.signature = encode_signature(&signature)?;
        Ok(record)
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct NativeProbe {
    pub(crate) calls: std::sync::atomic::AtomicUsize,
    pub(crate) checks: std::sync::atomic::AtomicUsize,
    pub(crate) fail: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use std::io::Write;
    use transport::auth::{auth_challenge, auth_challenge_v2, AuthSigner, AuthVerifier};

    use crate::record::decode_signature;

    fn rsa_native_fixture() -> FileSigner {
        let pair = ssh_key::private::RsaKeypair::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            2048,
        )
        .expect("generated RSA fixture");
        FileSigner::from_key(
            PrivateKey::new(ssh_key::private::KeypairData::Rsa(pair), "generated").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn native_rsa_prepares_once_per_owner_and_supports_concurrent_proofs() {
        use std::sync::{atomic::Ordering, Arc};
        let signer = Arc::new(rsa_native_fixture().with_login("generated".into()));
        let probe = signer.key.native_probe().unwrap().clone();
        assert_eq!(probe.checks.load(Ordering::SeqCst), 1);
        let workers: Vec<_> = (0..4)
            .map(|id| {
                let signer = signer.clone();
                std::thread::spawn(move || {
                    let hash = [id; 32];
                    let record = signer.sign(&hash, Some(&[3; 16])).unwrap();
                    let signature = decode_signature(&record.signature).unwrap();
                    signature::Verifier::verify(
                        signer.public_key(),
                        &record_challenge(&hash, &record),
                        &signature,
                    )
                    .unwrap();
                    assert!(signature::Verifier::verify(
                        signer.public_key(),
                        b"changed",
                        &signature
                    )
                    .is_err());
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            probe.checks.load(Ordering::SeqCst),
            1,
            "proofs do not revalidate private factors"
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn native_rsa_route_is_observed_on_the_real_file_signer() {
        use std::sync::{atomic::Ordering, Arc};
        let mut signer = rsa_native_fixture();
        let probe = Arc::new(NativeProbe::default());
        signer.native_probe = Some(probe.clone());
        let record = signer.sign(&[17; 32], None).expect("sign generated RSA");
        let signature = decode_signature(&record.signature).unwrap();
        signature::Verifier::verify(signer.public_key(), &auth_challenge(&[17; 32]), &signature)
            .unwrap();
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            1,
            "native private signing must run"
        );
    }

    #[test]
    fn native_rsa_failure_cannot_fall_back_to_a_successful_file_proof() {
        use std::sync::{atomic::Ordering, Arc};
        let mut signer = rsa_native_fixture();
        let probe = Arc::new(NativeProbe::default());
        probe.fail.store(true, Ordering::SeqCst);
        signer.native_probe = Some(probe.clone());
        assert!(
            signer.sign(&[19; 32], None).is_err(),
            "a native failure must prevent any proof"
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_dependency_enabled_p521_key_remains_unsupported_by_qsh() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP521,
            },
        )
        .expect("upstream supports P-521 in the workspace feature union");
        assert!(matches!(
            FileSigner::from_key(key).unwrap().sign(&[3; 32], None),
            Err(AuthError::Backend(_))
        ));
    }

    fn write_key(key: &PrivateKey, passphrase: Option<&str>) -> tempfile::NamedTempFile {
        let pem = match passphrase {
            None => key.to_openssh(LineEnding::LF).expect("encode"),
            Some(p) => key
                .encrypt(
                    &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                    p,
                )
                .expect("encrypt")
                .to_openssh(LineEnding::LF)
                .expect("encode"),
        };
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(pem.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    /// The signer's output is exactly what the server-side verifier accepts --
    /// the two halves are tested against each other, not against a fixture.
    #[test]
    fn a_file_signer_produces_a_record_the_verifier_accepts() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let key_file = write_key(&key, None);
        let signer = FileSigner::load(key_file.path(), None).expect("load");

        let mut authorized = tempfile::NamedTempFile::new().expect("temp file");
        authorized
            .write_all(format!("{}\n", key.public_key().to_openssh().unwrap()).as_bytes())
            .expect("write");
        authorized.flush().expect("flush");

        let hash = [11u8; 32];
        let record = signer.sign(&hash, None).expect("sign");
        let verifier = crate::verify::AuthorizedKeysVerifier::new(
            authorized.path().to_path_buf(),
            1000,
            "test".to_string(),
        );
        verifier
            .verify(&hash, &record, [0u8; 16], "")
            .expect("the verifier accepts our own proof");
    }

    /// A companion test pins this same obligation on the verifying side
    /// without depending on any signer
    /// (`verify::signing_the_raw_hash_instead_of_the_challenge_is_refused`).
    /// This pins the signer's side the same way, without depending on
    /// `AuthorizedKeysVerifier` continuing to reconstruct the challenge
    /// itself: it decodes the record's own bytes and checks both ways the
    /// signature could be interpreted directly. A signer that (by mistake)
    /// signed the bare hash would make the first assertion below fail.
    #[test]
    fn the_record_signs_the_challenge_not_the_bare_hash() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let key_file = write_key(&key, None);
        let signer = FileSigner::load(key_file.path(), None).expect("load");

        let hash = [7u8; 32];
        let record = signer.sign(&hash, None).expect("sign");
        let public_key = crate::record::decode_public_key(&record.public_key).expect("decode key");
        let sig = crate::record::decode_signature(&record.signature).expect("decode sig");

        // `PublicKey::verify(namespace, msg, &SshSig)` is a different,
        // inherent method that shadows the `signature::Verifier` trait
        // method used here -- hence the fully-qualified form.
        assert!(
            signature::Verifier::verify(&public_key, &hash, &sig).is_err(),
            "a signature made over auth_challenge(hash) must not also verify over the bare hash"
        );
        signature::Verifier::verify(&public_key, &auth_challenge(&hash), &sig)
            .expect("the signature verifies over the actual challenge it was made for");
    }

    /// With a nonce and a login, the signer produces a version 2 record whose
    /// signature verifies over the version 2 challenge -- not the version 1 one.
    #[test]
    fn a_nonce_and_a_login_make_a_version_2_record() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let signer = FileSigner::from_key(key.clone())
            .unwrap()
            .with_login("alice".to_string());
        let hash = [21u8; 32];
        let nonce = [4u8; 16];

        let record = signer.sign(&hash, Some(&nonce)).expect("sign");

        let v2 = record.v2.clone().expect("a nonce must produce a v2 record");
        assert_eq!(v2.login, "alice");
        assert_eq!(v2.nonce, nonce);
        let signature = decode_signature(&record.signature).expect("signature decodes");
        signature::Verifier::verify(key.public_key(), &auth_challenge_v2(&hash, &v2), &signature)
            .expect("the signature must verify over the v2 challenge");
    }

    /// Without a nonce the server is too old for version 2, so a version 1
    /// record is the only thing it would accept.
    #[test]
    fn no_nonce_means_a_version_1_record() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let signer = FileSigner::from_key(key)
            .unwrap()
            .with_login("alice".to_string());
        let record = signer.sign(&[21u8; 32], None).expect("sign");
        assert!(record.v2.is_none());
    }

    /// A signer with no login configured cannot make a v2 record, and says so
    /// rather than silently falling back to v1 -- a silent downgrade would
    /// hand a system-mode server a record it must refuse.
    #[test]
    fn a_nonce_without_a_login_is_an_error() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let signer = FileSigner::from_key(key).unwrap();
        assert!(matches!(
            signer.sign(&[21u8; 32], Some(&[4u8; 16])),
            Err(AuthError::Backend(_))
        ));
    }

    #[test]
    fn an_encrypted_key_without_a_passphrase_is_refused() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let key_file = write_key(&key, Some("hunter2"));
        assert!(
            matches!(
                FileSigner::load(key_file.path(), None),
                Err(AuthError::Backend(_))
            ),
            "an encrypted key without a passphrase cannot be loaded"
        );
    }

    #[test]
    fn an_encrypted_key_with_the_wrong_passphrase_is_refused() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let key_file = write_key(&key, Some("hunter2"));
        assert!(
            matches!(
                FileSigner::load(key_file.path(), Some("not-it")),
                Err(AuthError::Backend(_))
            ),
            "the wrong passphrase must not unlock the key"
        );
    }

    #[test]
    fn an_encrypted_key_with_its_passphrase_loads() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let key_file = write_key(&key, Some("hunter2"));
        FileSigner::load(key_file.path(), Some("hunter2")).expect("loads with the passphrase");
    }

    /// A passphrase offered for a key that turns out not to need one is
    /// simply ignored -- matching OpenSSH's own tolerance of an unnecessary
    /// passphrase -- and must not itself be treated as an error. This pins
    /// that as deliberate rather than accidental.
    #[test]
    fn a_passphrase_for_an_unencrypted_key_is_harmlessly_ignored() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let key_file = write_key(&key, None);
        FileSigner::load(key_file.path(), Some("unused"))
            .expect("an unneeded passphrase is not an error");
    }

    #[test]
    fn a_public_key_file_is_not_a_private_key() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(key.public_key().to_openssh().unwrap().as_bytes())
            .expect("write");
        f.flush().expect("flush");
        assert!(matches!(
            FileSigner::load(f.path(), None),
            Err(AuthError::Backend(_))
        ));
    }

    #[test]
    fn a_missing_file_reports_a_backend_error() {
        assert!(matches!(
            FileSigner::load(Path::new("/nonexistent/id_ed25519"), None),
            Err(AuthError::Backend(_))
        ));
    }
}
