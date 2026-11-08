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

fn ppk_v3_with_private_blob(key: &PrivateKey, private_blob: &[u8]) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let public = key.public_key().to_bytes().unwrap();

    let string = |buffer: &mut Vec<u8>, value: &[u8]| {
        buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buffer.extend_from_slice(value);
    };
    // PPK v3's unencrypted form authenticates five SSH strings with an empty
    // HMAC-SHA256 key. Only this test's generated material is serialized.
    let mut authenticated = Vec::new();
    for field in [
        b"ssh-ed25519".as_slice(),
        b"none",
        b"generated fixture",
        &public,
        private_blob,
    ] {
        string(&mut authenticated, field);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&[]).unwrap();
    mac.update(&authenticated);
    let digest = mac.finalize().into_bytes();
    let mac_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let b64 = base64::engine::general_purpose::STANDARD;
    format!(
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: generated fixture\nPublic-Lines: 1\n{}\nPrivate-Lines: 1\n{}\nPrivate-MAC: {}\n",
        b64.encode(public), b64.encode(private_blob), mac_hex,
    )
}

fn canonical_ppk_private_blob(key: &PrivateKey) -> Vec<u8> {
    use ssh_encoding::Encode;
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    let mut private = Vec::new();
    ssh_key::Mpint::from_positive_bytes(&seed)
        .encode(&mut private)
        .unwrap();
    private
}

fn canonical_ppk_v3(key: &PrivateKey) -> String {
    ppk_v3_with_private_blob(key, &canonical_ppk_private_blob(key))
}

fn boundary_key(prefix: &[u8]) -> PrivateKey {
    use ssh_key::rand_core::TryRng;
    let mut seed = [0u8; 32];
    ssh_key::getrandom::SysRng
        .try_fill_bytes(&mut seed)
        .unwrap();
    seed[..prefix.len()].copy_from_slice(prefix);
    key_from_seed(&seed)
}

fn key_from_seed(seed: &[u8; 32]) -> PrivateKey {
    PrivateKey::new(
        KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(seed)),
        "generated boundary test",
    )
    .unwrap()
}

fn boundary_keys() -> Vec<PrivateKey> {
    [
        &[0, 1][..],
        &[0, 0, 1],
        &[0, 0x80],
        &[0x7f],
        &[0x80],
        &[0xff],
    ]
    .into_iter()
    .map(boundary_key)
    .chain(std::iter::once(key_from_seed(&[0; 32])))
    .collect()
}

#[test]
fn ppk_fixture_integer_encoding_is_canonical() {
    for key in boundary_keys() {
        let seed = key.key_data().ed25519().unwrap().private.to_bytes();
        let blob = canonical_ppk_private_blob(&key);
        let integer = &blob[4..];
        let first_nonzero = seed.iter().position(|byte| *byte != 0).unwrap_or(32);
        let magnitude = &seed[first_nonzero..];
        let sign_byte = usize::from(magnitude.first().is_some_and(|byte| *byte >= 0x80));
        assert_eq!(integer.len(), magnitude.len() + sign_byte);
        assert_eq!(
            u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize,
            integer.len()
        );
        assert!(
            integer.is_empty() || integer[0] < 0x80,
            "positive integer sign"
        );
        assert!(
            integer.len() < 2 || integer[0] != 0 || integer[1] >= 0x80,
            "no redundant positive sign byte"
        );
        assert!(
            integer[sign_byte..] == *magnitude,
            "same big-endian magnitude"
        );
        let mut recovered = [0; 32];
        recovered[first_nonzero..].copy_from_slice(&integer[sign_byte..]);
        assert!(
            recovered == seed,
            "original seed order and leading zeros restored"
        );
    }
}

#[test]
fn canonical_ppk_seed_boundaries_preserve_the_signing_identity() {
    for key in boundary_keys() {
        check_openssh_control(&key);
        let text = canonical_ppk_v3(&key);
        for field in [
            "Private-MAC:",
            "Comment:",
            "Public-Lines:",
            "Private-Lines:",
        ] {
            assert_original_mac_failure(&tamper_ppk(&text, field));
        }
        let decoded =
            PrivateKey::from_ppk(&text, None).expect("decode canonical positive PPK integer");
        assert!(
            decoded.key_data().ed25519().unwrap().private.to_bytes()
                == key.key_data().ed25519().unwrap().private.to_bytes(),
            "same seed"
        );
        let shared = sshauth::keyfile::decode(&text).expect("shared decoder accepts canonical PPK");
        assert_eq!(
            shared.public_key().to_bytes().unwrap(),
            key.public_key().to_bytes().unwrap()
        );
        check_format(&key, &text);
    }
}

// Change exactly one original field without recomputing the MAC. No key or
// container bytes are included in assertion diagnostics.
fn tamper_ppk(text: &str, field: &str) -> String {
    use base64::Engine;
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let i = lines
        .iter()
        .position(|line| line.starts_with(field))
        .unwrap();
    match field {
        "Private-MAC:" => {
            let last = lines[i].pop().unwrap();
            lines[i].push(if last == '0' { '1' } else { '0' });
        }
        "Comment:" => lines[i].push('!'),
        _ => {
            let b64 = base64::engine::general_purpose::STANDARD;
            let mut bytes = b64.decode(&lines[i + 1]).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            lines[i + 1] = b64.encode(bytes);
        }
    }
    lines.join("\n") + "\n"
}

fn assert_original_mac_failure(text: &str) {
    // PpkParseError is private upstream; compare its safe public error category
    // and fixed Display value, never a parsed container or private material.
    let Err(error) = PrivateKey::from_ppk(text, None) else {
        panic!("tampered PPK must fail");
    };
    assert!(
        matches!(error, ssh_key::Error::Ppk(ref ppk) if ppk.to_string() == "incorrect MAC"),
        "original MAC rejected first"
    );
    assert!(sshauth::keyfile::decode(text).is_err());
}

#[test]
fn ppk_original_mac_is_required_before_integer_decoding() {
    let key = boundary_key(&[0x7f]);
    let valid = canonical_ppk_v3(&key);
    assert!(
        PrivateKey::from_ppk(&valid, None).is_ok(),
        "valid MAC control"
    );
    for field in [
        "Private-MAC:",
        "Comment:",
        "Public-Lines:",
        "Private-Lines:",
    ] {
        assert_original_mac_failure(&tamper_ppk(&valid, field));
    }
    // Authenticated noncanonical input fails integer decoding, while the same
    // input with an invalid MAC must fail authentication before that decoding.
    let malformed = ppk_v3_with_private_blob(&key, &integer_blob(&[0, 1]));
    let Err(error) = PrivateKey::from_ppk(&malformed, None) else {
        panic!("redundant zero integer must fail");
    };
    assert!(
        !matches!(error, ssh_key::Error::Ppk(_)),
        "MAC accepted before integer rejection"
    );
    assert!(sshauth::keyfile::decode(&malformed).is_err());
    assert_original_mac_failure(&tamper_ppk(&malformed, "Private-MAC:"));
}

fn integer_blob(integer: &[u8]) -> Vec<u8> {
    let mut blob = (integer.len() as u32).to_be_bytes().to_vec();
    blob.extend_from_slice(integer);
    blob
}

#[test]
fn ppk_invalid_integer_boundaries_are_rejected() {
    let key = boundary_key(&[0x7f]);
    for integer in [&[0, 1][..], &[0, 0, 1], &[0], &[0x80], &[0xff], &[1; 33]] {
        let text = ppk_v3_with_private_blob(&key, &integer_blob(integer));
        assert!(
            PrivateKey::from_ppk(&text, None).is_err(),
            "invalid integer rejected upstream"
        );
        assert!(
            sshauth::keyfile::decode(&text).is_err(),
            "invalid integer rejected at shared boundary"
        );
    }
    let negative_key = boundary_key(&[0x80]);
    let seed = negative_key
        .key_data()
        .ed25519()
        .unwrap()
        .private
        .to_bytes();
    let text = ppk_v3_with_private_blob(&negative_key, &integer_blob(&seed));
    assert!(
        PrivateKey::from_ppk(&text, None).is_err(),
        "negative raw seed rejected"
    );
    assert!(
        sshauth::keyfile::decode(&text).is_err(),
        "negative seed rejected by shared decoder"
    );
}

#[test]
fn ppk_encrypted_container_policy_remains_unsupported() {
    let text = canonical_ppk_v3(&boundary_key(&[0x7f])).replacen(
        "Encryption: none",
        "Encryption: aes256-cbc",
        1,
    );
    assert!(matches!(
        sshauth::keyfile::decode(&text),
        Err(sshauth::keyfile::KeyFileError::UnsupportedEncryptedPpk)
    ));
}

#[test]
fn generated_unencrypted_ppk_preserves_the_signing_identity() {
    let key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap();
    check_format(&key, &canonical_ppk_v3(&key));
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
