//! Ordinary private-key encodings must preserve the identity and signing key.
//! Every private fixture is generated in memory and confined to a temporary file.
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

#[derive(Clone, Copy, Debug)]
enum PpkVersion {
    V2,
    V3,
}

// Serialize an unencrypted PPK exactly as PuTTY's writer does: 64-column
// Base64 lines and the MAC over the five authenticated SSH strings. Only this
// test's generated material is serialized.
fn ppk_with_private_blob(
    version: PpkVersion,
    key: &PrivateKey,
    comment: &str,
    private_blob: &[u8],
) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Digest;
    let public = key.public_key().to_bytes().unwrap();

    let string = |buffer: &mut Vec<u8>, value: &[u8]| {
        buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buffer.extend_from_slice(value);
    };
    let mut authenticated = Vec::new();
    for field in [
        &b"ssh-ed25519"[..],
        b"none",
        comment.as_bytes(),
        &public,
        private_blob,
    ] {
        string(&mut authenticated, field);
    }
    // Without encryption, v2 keys HMAC-SHA1 with the hash of the fixed prefix
    // and v3 keys HMAC-SHA256 with an empty key.
    let mac = match version {
        PpkVersion::V2 => {
            let key = sha1::Sha1::digest(b"putty-private-key-file-mac-key");
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();
            mac.update(&authenticated);
            mac.finalize().into_bytes().to_vec()
        }
        PpkVersion::V3 => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&[]).unwrap();
            mac.update(&authenticated);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let mac_hex: String = mac.iter().map(|byte| format!("{byte:02x}")).collect();
    let lines = |bytes: &[u8]| {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        format!("{}\n{}", lines.len(), lines.join("\n"))
    };
    let number = match version {
        PpkVersion::V2 => 2,
        PpkVersion::V3 => 3,
    };
    format!(
        "PuTTY-User-Key-File-{number}: ssh-ed25519\nEncryption: none\nComment: {comment}\nPublic-Lines: {}\nPrivate-Lines: {}\nPrivate-MAC: {mac_hex}\n",
        lines(&public),
        lines(private_blob),
    )
}

fn ppk_v3_with_private_blob(key: &PrivateKey, private_blob: &[u8]) -> String {
    ppk_with_private_blob(PpkVersion::V3, key, "generated fixture", private_blob)
}

/// PuTTY documents an mpint but writes the seed's little-endian integer as a
/// plain string. Since 0.75 it is exactly 32 bytes (`put_mp_le_fixedlen`).
fn putty_ppk_private_blob(key: &PrivateKey) -> Vec<u8> {
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    integer_blob(&seed)
}

/// PuTTY 0.74 and earlier (`put_mp_le_unsigned`) trim high zero bytes, which
/// are the seed's trailing bytes.
fn legacy_putty_ppk_private_blob(key: &PrivateKey) -> Vec<u8> {
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    let length = seed
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |i| i + 1);
    integer_blob(&seed[..length])
}

fn putty_ppk_v3(key: &PrivateKey) -> String {
    ppk_v3_with_private_blob(key, &putty_ppk_private_blob(key))
}

// Each layout PuTTY has written for unencrypted Ed25519 keys.
fn putty_ppk_layouts(key: &PrivateKey) -> [(&'static str, String); 3] {
    let comment = "generated fixture";
    [
        ("v3", putty_ppk_v3(key)),
        (
            "v2",
            ppk_with_private_blob(PpkVersion::V2, key, comment, &putty_ppk_private_blob(key)),
        ),
        (
            "legacy v2",
            ppk_with_private_blob(
                PpkVersion::V2,
                key,
                comment,
                &legacy_putty_ppk_private_blob(key),
            ),
        ),
    ]
}

fn boundary_key(prefix: &[u8], suffix: &[u8]) -> PrivateKey {
    use ssh_key::rand_core::TryRng;
    let mut seed = [0u8; 32];
    ssh_key::getrandom::SysRng
        .try_fill_bytes(&mut seed)
        .unwrap();
    seed[..prefix.len()].copy_from_slice(prefix);
    seed[32 - suffix.len()..].copy_from_slice(suffix);
    // A zero suffix is exactly the number of bytes PuTTY 0.74 trims.
    if !suffix.is_empty() && suffix.iter().all(|byte| *byte == 0) {
        seed[31 - suffix.len()] |= 1;
    }
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
        (&[0, 1][..], &[][..]),
        (&[0, 0, 1], &[]),
        (&[0, 0x80], &[]),
        (&[0x7f], &[]),
        (&[0x80], &[]),
        (&[0xff], &[]),
        (&[0x80], &[0]),
        (&[0x7f], &[0, 0]),
        (&[0, 0x80], &[0x80]),
    ]
    .into_iter()
    .map(|(prefix, suffix)| boundary_key(prefix, suffix))
    .chain(std::iter::once(key_from_seed(&[0; 32])))
    .collect()
}

#[test]
fn ppk_fixture_private_fields_match_putty_layouts() {
    for key in boundary_keys() {
        let seed = key.key_data().ed25519().unwrap().private.to_bytes();
        let fixed = putty_ppk_private_blob(&key);
        assert_eq!(fixed[..4], 32u32.to_be_bytes());
        assert!(fixed[4..] == seed, "fixed-width little-endian seed");

        let legacy = legacy_putty_ppk_private_blob(&key);
        let length = u32::from_be_bytes(legacy[..4].try_into().unwrap()) as usize;
        assert_eq!(legacy.len(), 4 + length);
        assert!(legacy[4..] == seed[..length], "unchanged low-order bytes");
        assert!(
            seed[length..].iter().all(|byte| *byte == 0),
            "only zero high-order bytes trimmed"
        );
        assert!(length == 0 || seed[length - 1] != 0, "minimal length");
    }
}

#[test]
fn putty_ppk_seed_boundaries_preserve_the_signing_identity() {
    for key in boundary_keys() {
        check_openssh_control(&key);
        for (layout, text) in putty_ppk_layouts(&key) {
            for field in [
                "Private-MAC:",
                "Comment:",
                "Public-Lines:",
                "Private-Lines:",
            ] {
                assert_original_mac_failure(&tamper_ppk(&text, field));
            }
            let decoded = PrivateKey::from_ppk(&text, None)
                .unwrap_or_else(|_| panic!("decode PuTTY {layout} private field"));
            assert!(
                decoded.key_data().ed25519().unwrap().private.to_bytes()
                    == key.key_data().ed25519().unwrap().private.to_bytes(),
                "same seed from PuTTY {layout} private field"
            );
            let shared = sshauth::keyfile::decode(&text)
                .unwrap_or_else(|_| panic!("shared decoder accepts PuTTY {layout} field"));
            assert_eq!(
                shared.public_key().to_bytes().unwrap(),
                key.public_key().to_bytes().unwrap()
            );
            check_format(&key, &text);
        }
    }
}

// Seeds of public interoperability vectors: SHA-256 of a fixed label and a
// big-endian index. Only these test keys are derived; nothing grants access.
fn interop_key(index: u32) -> PrivateKey {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(b"qsh PPK Ed25519 interop vector");
    hash.update(index.to_be_bytes());
    key_from_seed(&hash.finalize().into())
}

// SHA-256 of the unencrypted files that official puttygen releases write from
// the OpenSSH export of `interop_key(index)` with comment `qsh interop
// <index>`: `puttygen <file> -O private`, plus `--ppk-param version=2` for
// 0.85's v2 files. Vector 1 has a seed whose first byte is at least 0x80 and
// vector 439 a seed whose last byte is zero, which 0.74 trims. The fixture
// serializer must reproduce each file byte for byte; the files themselves are
// not committed.
const PUTTYGEN_VECTORS: &[(&str, u32, PpkVersion, bool, &str)] = &[
    (
        "0.85",
        0,
        PpkVersion::V3,
        false,
        "4ed53524d09b140d9b4ac5f4681e1f4131a6e910d2b6a8ecfcec9efb6029961b",
    ),
    (
        "0.85",
        1,
        PpkVersion::V3,
        false,
        "edb877e388bbbb5bf22b1abaef7473674b925a3f8765c19fe7df6bf3f224a88d",
    ),
    (
        "0.85",
        439,
        PpkVersion::V3,
        false,
        "9e17fea430dcb6008594e75d86a37ec81cf78948505a5520951a312925a515e8",
    ),
    (
        "0.85 and 0.74",
        0,
        PpkVersion::V2,
        false,
        "20b49f8e9e723d18487efc2df20ea1130443ec6700ab4f3a08c0635c66ac7951",
    ),
    (
        "0.85 and 0.74",
        1,
        PpkVersion::V2,
        false,
        "47fafb012cb97acb9d0f4361f15d2eb0147da167e0e63162cbff7e90fd2f9762",
    ),
    (
        "0.85",
        439,
        PpkVersion::V2,
        false,
        "e5301df184bdad6ed5a39bb71cfa3ed25cb19790c8575d5fe0fbb59234060e12",
    ),
    (
        "0.74",
        439,
        PpkVersion::V2,
        true,
        "454a3e20ee22dae4636cb205eab0eb2c00a0a30c9af4a929795edc2827b95ab6",
    ),
];

#[test]
fn ppk_fixture_serializer_reproduces_puttygen_files() {
    use sha2::Digest;
    for &(release, index, version, legacy, expected) in PUTTYGEN_VECTORS {
        let key = interop_key(index);
        let blob = if legacy {
            legacy_putty_ppk_private_blob(&key)
        } else {
            putty_ppk_private_blob(&key)
        };
        let comment = format!("qsh interop {index}");
        let text = ppk_with_private_blob(version, &key, &comment, &blob);
        let digest: String = sha2::Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(digest, expected, "PuTTY {release} vector {index}");
        let decoded = sshauth::keyfile::decode(&text).expect("decode the PuTTY vector");
        assert_eq!(
            decoded.public_key().to_bytes().unwrap(),
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
fn ppk_original_mac_is_required_before_private_field_decoding() {
    let key = boundary_key(&[0x7f], &[]);
    let valid = putty_ppk_v3(&key);
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
    // An authenticated overwidth field fails private decoding, while the same
    // input with an invalid MAC must fail authentication before that decoding.
    let malformed = ppk_v3_with_private_blob(&key, &integer_blob(&[1; 33]));
    let Err(error) = PrivateKey::from_ppk(&malformed, None) else {
        panic!("overwidth private field must fail");
    };
    assert!(
        !matches!(error, ssh_key::Error::Ppk(_)),
        "MAC accepted before private field rejection"
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
fn ppk_invalid_private_fields_are_rejected() {
    let key = boundary_key(&[0x80], &[]);
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    // A sign-prefixed big-endian mpint is not PuTTY's layout: PuTTY would read
    // it as a different integer.
    let mut signed = vec![0];
    signed.extend_from_slice(&seed);
    let mut reversed = seed;
    reversed.reverse();
    let mut other = seed;
    other[0] ^= 1;
    let mut truncated = integer_blob(&seed);
    truncated.pop();
    // Every authenticated field is well formed as a container value; each
    // must still fail because it is overwidth, malformed or derives a
    // different public key than the container's.
    for blob in [
        integer_blob(&[1; 33]),
        integer_blob(&signed),
        integer_blob(&reversed),
        integer_blob(&other),
        integer_blob(&seed[1..]),
        integer_blob(&[0, 1]),
        integer_blob(&[0x80]),
        integer_blob(&[]),
        truncated,
    ] {
        let text = ppk_v3_with_private_blob(&key, &blob);
        assert!(
            PrivateKey::from_ppk(&text, None).is_err(),
            "invalid private field rejected upstream"
        );
        assert!(
            sshauth::keyfile::decode(&text).is_err(),
            "invalid private field rejected at shared boundary"
        );
    }
}

#[test]
fn ppk_encrypted_container_policy_remains_unsupported() {
    let text = putty_ppk_v3(&boundary_key(&[0x7f], &[])).replacen(
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
    for (_, text) in putty_ppk_layouts(&key) {
        check_format(&key, &text);
    }
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
