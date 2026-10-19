//! Password requests are reserved for locked OpenSSH files, never parse errors.
#[path = "support/key_formats.rs"]
mod formats;

use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::{keyfile::KeyFileError, sign_file::FileSigner};

fn key() -> PrivateKey {
    PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap()
}

#[test]
fn locked_openssh_distinguishes_password_request_from_failed_decryption() {
    let key = key();
    let locked = key
        .encrypt(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            "generated format passphrase",
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("identity");
    std::fs::write(&file, locked.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    assert!(matches!(
        FileSigner::load_classified(&file, None),
        Err(KeyFileError::PassphraseRequired)
    ));
    assert!(matches!(
        FileSigner::load_classified(&file, Some("wrong")),
        Err(KeyFileError::DecryptionFailed)
    ));
    let loaded = FileSigner::load_classified(&file, Some("generated format passphrase")).unwrap();
    assert_eq!(loaded.public_key(), key.public_key());
}

#[test]
fn invalid_and_unreadable_files_never_become_passphrase_requests() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("identity");
    for bytes in [b"PRIVATE_INPUT_SENTINEL\x1b[2J".as_slice(), &[0xff, 0xfe]] {
        std::fs::write(&file, bytes).unwrap();
        let error = FileSigner::load_classified(&file, None)
            .err()
            .expect("invalid key");
        assert!(!matches!(error, KeyFileError::PassphraseRequired));
        assert!(!format!("{error:?} {error}").contains("PRIVATE_INPUT_SENTINEL"));
        assert!(!format!("{error:?} {error}").contains('\x1b'));
    }
    std::fs::write(&file, key().public_key().to_openssh().unwrap()).unwrap();
    assert!(matches!(
        FileSigner::load_classified(&file, None),
        Err(KeyFileError::InvalidFormat)
    ));
    assert!(matches!(
        FileSigner::load_classified(dir.path(), None),
        Err(KeyFileError::Io(_))
    ));
    assert!(matches!(
        FileSigner::load_classified(&dir.path().join("missing"), None),
        Err(KeyFileError::Io(_))
    ));
}

#[test]
fn generated_encrypted_pem_and_pkcs8_are_explicitly_unsupported_even_with_password() {
    use p256::elliptic_curve::Generate;
    let private = p256::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::write(
        &source,
        private.to_sec1_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    for (name, args) in [
        (
            "legacy",
            vec!["ec", "-aes256", "-passout", "pass:generated-fixture"],
        ),
        (
            "pkcs8",
            vec![
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-passout",
                "pass:generated-fixture",
            ],
        ),
    ] {
        let path = dir.path().join(name);
        formats::openssl(&source, &path, &args);
        let encoded = std::fs::read_to_string(&path).unwrap();
        for preamble in ["", "Bag Attributes\n    friendlyName: generated fixture\n"] {
            std::fs::write(&path, format!("{preamble}{encoded}")).unwrap();
            for password in [None, Some("generated-fixture")] {
                assert!(
                    matches!(
                        FileSigner::load_classified(&path, password),
                        Err(KeyFileError::UnsupportedEncryptedFormat)
                    ),
                    "{name} must not enter the OpenSSH password flow"
                );
            }
        }
    }
}

#[test]
fn explicit_ec_disposition_never_covers_invalid_or_other_containers() {
    use p256::elliptic_curve::Generate;
    use pkcs8::der::{asn1::AnyRef, Decode, Encode, SecretDocument, Tag};
    let private = p256::SecretKey::generate_from_rng(&mut ssh_key::rand_core::UnwrapErr(
        ssh_key::getrandom::SysRng,
    ));
    let dir = tempfile::tempdir().unwrap();
    let named = dir.path().join("named");
    let explicit = dir.path().join("explicit");
    let named_text = private.to_sec1_pem(LineEnding::LF).unwrap();
    std::fs::write(&named, named_text.as_bytes()).unwrap();
    formats::openssl(&named, &explicit, &["ec", "-param_enc", "explicit"]);
    let text = std::fs::read_to_string(&explicit).unwrap();
    assert!(matches!(
        sshauth::keyfile::decode(&text),
        Err(KeyFileError::ExplicitEcParameters)
    ));
    assert!(sshauth::keyfile::decode(&named_text).is_ok());
    assert!(!matches!(
        sshauth::keyfile::decode(&text.replace("EC PRIVATE KEY", "PRIVATE KEY")),
        Err(KeyFileError::ExplicitEcParameters)
    ));
    let (_, doc) = SecretDocument::from_pem(&text).unwrap();
    let body = AnyRef::from_der(doc.as_bytes()).unwrap();
    // A syntactically valid DER sequence with an extra field is not a valid
    // SEC1 envelope, so it cannot obtain the special upstream route.
    let mut trailing = body.value().to_vec();
    trailing.extend_from_slice(&[0x05, 0]);
    let invalid_der = AnyRef::new(Tag::Sequence, &trailing)
        .unwrap()
        .to_der()
        .unwrap();
    let invalid = SecretDocument::try_from(invalid_der)
        .unwrap()
        .to_pem("EC PRIVATE KEY", LineEnding::LF)
        .unwrap();
    assert!(matches!(
        sshauth::keyfile::decode(&invalid),
        Err(KeyFileError::InvalidFormat)
    ));
    assert!(matches!(
        sshauth::keyfile::decode(&format!("{text}{}", named_text.as_str())),
        Err(KeyFileError::InvalidFormat)
    ));
}

#[test]
fn named_curve_validation_never_uses_the_explicit_parameter_route() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::elliptic_curve::Generate;
    use pkcs8::{AssociatedOid, SecretDocument};
    let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
    let private = p256::SecretKey::generate_from_rng(&mut rng);
    let other = p256::SecretKey::generate_from_rng(&mut rng);
    let secret_bytes = private.to_bytes();
    let other_public = other.public_key().to_sec1_point(false);
    for (oid, public) in [
        (p256::NistP256::OID, Some(other_public.as_bytes())),
        ("1.2.3.4".parse().unwrap(), None),
    ] {
        let container = sec1::EcPrivateKey {
            private_key: &secret_bytes,
            parameters: Some(oid.into()),
            public_key: public,
        };
        let pem = SecretDocument::encode_msg(&container)
            .unwrap()
            .to_pem("EC PRIVATE KEY", LineEnding::LF)
            .unwrap();
        let error = sshauth::keyfile::decode(&pem).expect_err("invalid named-curve key");
        assert!(matches!(
            error,
            KeyFileError::InvalidFormat | KeyFileError::UnsupportedFormat
        ));
    }
}
