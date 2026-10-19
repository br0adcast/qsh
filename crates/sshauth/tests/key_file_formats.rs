//! Ordinary private-key encodings must preserve the identity and signing key.
//! Every private fixture is freshly generated and confined to a temporary file.
use std::io::Write;

use p256::elliptic_curve::Generate;
use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePrivateKey};
use ssh_key::{
    private::{EcdsaKeypair, KeypairData, RsaKeypair},
    Algorithm, LineEnding, PrivateKey,
};
use sshauth::sign_file::FileSigner;
use transport::auth::{AuthSigner, AuthVerifier};

fn check_format(original: &PrivateKey, encoded: &str) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(encoded.as_bytes()).unwrap();
    file.flush().unwrap();
    let signer = FileSigner::load(file.path(), None)
        .expect("load the generated ordinary private-key container")
        .with_login("format-fixture".into());
    assert_eq!(
        signer.public_key().to_bytes().unwrap(),
        original.public_key().to_bytes().unwrap(),
        "container decoding must preserve the public identity"
    );
    let mut authorized = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        authorized,
        "{}",
        original.public_key().to_openssh().unwrap()
    )
    .unwrap();
    authorized.flush().unwrap();
    let verifier = sshauth::verify::AuthorizedKeysVerifier::new(
        authorized.path().to_owned(),
        1000,
        "format-fixture".into(),
    );
    let challenge = [11; 32];
    let nonce = [23; 16];
    let record = signer
        .sign(&challenge, Some(&nonce))
        .expect("sign v2 proof");
    verifier
        .verify(&challenge, &record, nonce, "format-fixture")
        .expect("the generated authorized identity must verify the file's proof");
    assert!(verifier
        .verify(&[12; 32], &record, nonce, "format-fixture")
        .is_err());
}

fn rsa_key() -> PrivateKey {
    let pair = RsaKeypair::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        2048,
    )
    .expect("generate fixture RSA");
    PrivateKey::new(KeypairData::Rsa(pair), "generated format test").unwrap()
}

fn check_openssh_control(key: &PrivateKey) {
    check_format(key, &key.to_openssh(LineEnding::LF).unwrap());
}

#[test]
fn rsa_pkcs1_file_signs_as_the_same_openssh_identity() {
    let key = rsa_key();
    check_openssh_control(&key);
    let private = rsa::RsaPrivateKey::try_from(key.key_data().rsa().unwrap()).unwrap();
    check_format(&key, &private.to_pkcs1_pem(LineEnding::LF).unwrap());
}

#[test]
fn rsa_pkcs8_file_signs_as_the_same_openssh_identity() {
    let key = rsa_key();
    check_openssh_control(&key);
    let private = rsa::RsaPrivateKey::try_from(key.key_data().rsa().unwrap()).unwrap();
    check_format(&key, &private.to_pkcs8_pem(LineEnding::LF).unwrap());
}

#[test]
fn ed25519_pkcs8_file_signs_as_the_same_openssh_identity() {
    let key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    check_openssh_control(&key);
    let private = ed25519_dalek::SigningKey::try_from(key.key_data().ed25519().unwrap()).unwrap();
    check_format(&key, &private.to_pkcs8_pem(LineEnding::LF).unwrap());
}

fn ec_key() -> (PrivateKey, p256::SecretKey) {
    let private = p256::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let pair = EcdsaKeypair::NistP256 {
        public: private.public_key().into(),
        private: private.clone().into(),
    };
    let key = PrivateKey::new(KeypairData::Ecdsa(pair), "generated format test").unwrap();
    (key, private)
}

#[test]
fn named_curve_sec1_file_signs_as_the_same_openssh_identity() {
    let (key, private) = ec_key();
    check_openssh_control(&key);
    check_format(&key, &private.to_sec1_pem(LineEnding::LF).unwrap());
}

#[test]
fn ecdsa_pkcs8_file_signs_as_the_same_openssh_identity() {
    let (key, private) = ec_key();
    check_openssh_control(&key);
    check_format(&key, &private.to_pkcs8_pem(LineEnding::LF).unwrap());
}

#[test]
fn p384_named_curve_containers_preserve_the_signing_identity() {
    let private = p384::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let key = PrivateKey::new(
        KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
            public: private.public_key().into(),
            private: private.clone().into(),
        }),
        "generated format test",
    )
    .unwrap();
    check_openssh_control(&key);
    check_format(&key, &private.to_sec1_pem(LineEnding::LF).unwrap());
    check_format(&key, &private.to_pkcs8_pem(LineEnding::LF).unwrap());
}

#[test]
fn p521_containers_load_for_ssh_without_expanding_qsh_signature_policy() {
    let private = p521::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let public = PrivateKey::new(
        KeypairData::Ecdsa(EcdsaKeypair::NistP521 {
            public: private.public_key().into(),
            private: private.clone().into(),
        }),
        "generated format test",
    )
    .unwrap()
    .public_key()
    .to_bytes()
    .unwrap();
    for encoded in [
        private.to_sec1_pem(LineEnding::LF).unwrap(),
        private.to_pkcs8_pem(LineEnding::LF).unwrap(),
    ] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(encoded.as_bytes()).unwrap();
        let signer = FileSigner::load(file.path(), None)
            .expect("P-521 parsing stays available for SSH")
            .with_login("format-fixture".into());
        assert_eq!(signer.public_key().to_bytes().unwrap(), public);
        assert!(
            signer.sign(&[11; 32], Some(&[23; 16])).is_err(),
            "container support must not enable a forbidden QSH signature"
        );
    }
}
#[test]
fn generated_unencrypted_ppk_preserves_the_signing_identity() {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    let public = key.public_key().to_bytes().unwrap();
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    let mut private = Vec::new();
    let string = |buffer: &mut Vec<u8>, value: &[u8]| {
        buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buffer.extend_from_slice(value);
    };
    string(&mut private, &seed);
    // PPK v3's unencrypted form authenticates five SSH strings with an empty
    // HMAC-SHA256 key. Only this test's generated material is serialized.
    let mut authenticated = Vec::new();
    for field in [
        b"ssh-ed25519".as_slice(),
        b"none",
        b"generated fixture",
        &public,
        &private,
    ] {
        string(&mut authenticated, field);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&[]).unwrap();
    mac.update(&authenticated);
    let digest = mac.finalize().into_bytes();
    let mac_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let b64 = base64::engine::general_purpose::STANDARD;
    let text = format!(
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: generated fixture\nPublic-Lines: 1\n{}\nPrivate-Lines: 1\n{}\nPrivate-MAC: {}\n",
        b64.encode(public), b64.encode(private), mac_hex,
    );
    check_format(&key, &text);
}

#[test]
fn pkcs8_mime_wrapping_preserves_the_same_private_identity() {
    let key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    let private = ed25519_dalek::SigningKey::try_from(key.key_data().ed25519().unwrap()).unwrap();
    let canonical = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let base64: String = canonical
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with("-----END "))
        .collect();
    let mut mime = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in base64.as_bytes().chunks(76) {
        mime.push_str(std::str::from_utf8(chunk).unwrap());
        mime.push_str("\r\n");
    }
    // The existing russh PEM writer appends LF after BASE64_MIME's final CRLF.
    mime.push_str("\n-----END PRIVATE KEY-----\n");
    check_format(&key, &mime);
}

#[test]
fn annotated_pem_files_preserve_the_signing_identity() {
    let (key, private) = ec_key();
    for encoded in [
        private.to_sec1_pem(LineEnding::LF).unwrap(),
        private.to_pkcs8_pem(LineEnding::LF).unwrap(),
        key.to_openssh(LineEnding::LF).unwrap(),
    ] {
        let encoded = encoded.as_str();
        let annotated = format!(
            "Bag Attributes\n    friendlyName: generated fixture\nKey Attributes: <No Attributes>\nProc-Type: preamble is not an encryption header\n{encoded}"
        );
        check_format(&key, &annotated);
        assert!(matches!(
            sshauth::keyfile::decode(&format!("{annotated}{encoded}")),
            Err(sshauth::keyfile::KeyFileError::InvalidFormat)
        ));
    }
}
