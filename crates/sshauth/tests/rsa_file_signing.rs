//! Real generated RSA identity through the production file signer.
use std::io::Write;

use ssh_key::{
    private::{KeypairData, RsaKeypair},
    LineEnding, PrivateKey,
};
use sshauth::sign_file::FileSigner;
use transport::auth::{AuthSigner, AuthVerifier};

#[test]
fn generated_rsa_file_signs_a_challenge_the_authorized_verifier_accepts() {
    check_rsa_file(None);
}

#[test]
fn generated_encrypted_rsa_file_signs_both_auth_versions() {
    check_rsa_file(Some("generated fixture passphrase"));
}

fn check_rsa_file(passphrase: Option<&str>) {
    let pair = RsaKeypair::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        2048,
    )
    .expect("generate fixture RSA");
    let key = PrivateKey::new(KeypairData::Rsa(pair), "generated RSA test").expect("private key");
    let mut identity = tempfile::NamedTempFile::new().unwrap();
    let stored = match passphrase {
        Some(pass) => key
            .encrypt(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                pass,
            )
            .expect("encrypt fixture"),
        None => key.clone(),
    };
    identity
        .write_all(stored.to_openssh(LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    identity.flush().unwrap();
    let mut authorized = tempfile::NamedTempFile::new().unwrap();
    writeln!(authorized, "{}", key.public_key().to_openssh().unwrap()).unwrap();
    authorized.flush().unwrap();
    if passphrase.is_some() {
        assert!(FileSigner::load(identity.path(), None).is_err());
        assert!(FileSigner::load(identity.path(), Some("wrong passphrase")).is_err());
    }
    let signer =
        FileSigner::load(identity.path(), passphrase).expect("load generated RSA identity");
    let hash = [7; 32];
    let record = signer
        .sign(&hash, None)
        .expect("a loaded RSA identity must sign");
    let verifier = sshauth::verify::AuthorizedKeysVerifier::new(
        authorized.path().to_path_buf(),
        1000,
        "rsa-fixture".into(),
    );
    verifier
        .verify(&hash, &record, [0; 16], "")
        .expect("verify RSA file proof");
    assert!(record.v2.is_none());
    assert_eq!(
        sshauth::record::decode_signature(&record.signature)
            .unwrap()
            .algorithm(),
        ssh_key::Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha512)
        },
        "file RSA signing preserves SHA-512",
    );
    assert!(verifier.verify(&[8; 32], &record, [0; 16], "").is_err());
    let signer = signer.with_login("rsa-fixture".into());
    let nonce = [3; 16];
    let v2 = signer.sign(&hash, Some(&nonce)).expect("sign v2 RSA proof");
    verifier
        .verify(&hash, &v2, nonce, "rsa-fixture")
        .expect("verify v2 RSA proof");
    assert!(verifier
        .verify(&[8; 32], &v2, nonce, "rsa-fixture")
        .is_err());
    let mut altered = v2.clone();
    altered.v2.as_mut().unwrap().login = "different-login".into();
    assert!(verifier
        .verify(&hash, &altered, nonce, "different-login")
        .is_err());
    altered = v2.clone();
    altered.v2.as_mut().unwrap().nonce = [4; 16];
    assert!(verifier
        .verify(&hash, &altered, [4; 16], "rsa-fixture")
        .is_err());
}
