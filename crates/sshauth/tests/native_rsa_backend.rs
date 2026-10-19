//! Runtime-generated native RSA fixtures; no private material is printed.
use openssl::{bn::BigNum, rsa::Rsa};
use ssh_key::{Algorithm, HashAlg};
use sshauth::{
    keyfile::{self, KeyFileError},
    prepared_key::{PreparedKey, RsaDigest},
};
use zeroize::Zeroizing;

fn check(bits: u32, exponent: u32) {
    let generated = Rsa::generate_with_e(bits, &BigNum::from_u32(exponent).unwrap()).unwrap();
    let pem = Zeroizing::new(generated.private_key_to_pem().unwrap());
    let key = keyfile::decode(std::str::from_utf8(&pem).unwrap())
        .unwrap()
        .into_prepared(None)
        .unwrap();
    for (digest, expected) in [
        (RsaDigest::Sha1, None),
        (RsaDigest::Sha256, Some(HashAlg::Sha256)),
        (RsaDigest::Sha512, Some(HashAlg::Sha512)),
    ] {
        let signature = key.sign(b"generated native RSA fixture", digest).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: expected });
        signature::Verifier::verify(
            key.public_key(),
            b"generated native RSA fixture",
            &signature,
        )
        .unwrap();
        assert!(
            signature::Verifier::verify(key.public_key(), b"changed fixture", &signature).is_err()
        );
        let mut changed = signature.as_bytes().to_vec();
        changed[0] ^= 1;
        let changed = ssh_key::Signature::new(signature.algorithm(), changed).unwrap();
        assert!(signature::Verifier::verify(
            key.public_key(),
            b"generated native RSA fixture",
            &changed
        )
        .is_err());
    }
}

#[test]
fn native_rsa_preserves_sha1_sha256_sha512_and_small_exponents() {
    for exponent in [3, 65537] {
        check(2048, exponent);
    }
}

#[test]
#[ignore = "explicit generated large-key qualification"]
fn native_rsa_large_key_envelope() {
    for bits in [1024, 4096, 8192] {
        for exponent in [3, 65537] {
            check(bits, exponent);
        }
    }
}

#[test]
fn native_rsa_rejects_a_valid_multiprime_container() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("generated.pem");
    let scoped = format!(
        "{}_OPENSSL_DIR",
        env!("QSH_NATIVE_TARGET").to_uppercase().replace('-', "_")
    );
    let prefix = std::env::var_os(scoped)
        .or_else(|| std::env::var_os("OPENSSL_DIR"))
        .expect("qualified native prefix");
    let output = std::process::Command::new(std::path::PathBuf::from(prefix).join("bin/openssl"))
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-pkeyopt",
            "rsa_keygen_primes:3",
            "-out",
        ])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "generated multiprime fixture failed"
    );
    let text = Zeroizing::new(std::fs::read_to_string(file).unwrap());
    // The native library supports this key; shared accepted formats deliberately
    // retain the previous two-prime restriction before invoking it.
    assert!(openssl::pkey::PKey::private_key_from_pem(text.as_bytes())
        .unwrap()
        .rsa()
        .unwrap()
        .check_key()
        .unwrap());
    assert!(matches!(
        keyfile::decode(&text),
        Err(KeyFileError::InvalidFormat)
    ));
}

#[test]
fn malformed_private_components_are_rejected_during_owned_preparation() {
    use ssh_key::{
        private::{KeypairData, RsaKeypair, RsaPrivateKey},
        Mpint, PrivateKey,
    };
    let pair = RsaKeypair::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        2048,
    )
    .unwrap();
    let bad = RsaPrivateKey::new(
        Mpint::from_positive_bytes(&[3]),
        pair.private().iqmp().clone(),
        pair.private().p().clone(),
        pair.private().q().clone(),
    )
    .unwrap();
    let malformed = PrivateKey::new(
        KeypairData::Rsa(RsaKeypair::new(pair.public().clone(), bad).unwrap()),
        "generated malformed fixture",
    )
    .unwrap();
    assert!(PreparedKey::from_key(malformed).is_err());
}

#[test]
fn native_rsa_preserves_rfc5958_public_field_and_algorithm_parameter_policy() {
    use pkcs8::der::{asn1::BitStringRef, Decode, EncodePem};
    let rsa = Rsa::generate(2048).unwrap();
    let public = rsa.public_key_to_der_pkcs1().unwrap();
    let owner = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let der = Zeroizing::new(owner.private_key_to_pkcs8().unwrap());
    let mut info = pkcs8::PrivateKeyInfoRef::from_der(&der).unwrap();
    info.public_key = Some(BitStringRef::from_bytes(&public).unwrap());
    // The previous shared decoder accepts RFC5958's optional public field.
    assert!(rsa::RsaPrivateKey::try_from(info.clone()).is_ok());
    let pem = Zeroizing::new(info.to_pem(pkcs8::LineEnding::LF).unwrap());
    let key = keyfile::decode(&pem)
        .expect("preserve accepted RFC5958 wrapper")
        .into_prepared(None)
        .unwrap();
    let signed = key.sign(b"RFC5958 fixture", RsaDigest::Sha512).unwrap();
    signature::Verifier::verify(key.public_key(), b"RFC5958 fixture", &signed).unwrap();

    // rsaEncryption requires explicit NULL in the previous parser. Native
    // decoding must not silently expand that outer-wrapper acceptance policy.
    info.public_key = None;
    for parameters in [
        None,
        Some(pkcs8::der::asn1::AnyRef::new(pkcs8::der::Tag::OctetString, b"generated").unwrap()),
    ] {
        info.algorithm.parameters = parameters;
        assert!(rsa::RsaPrivateKey::try_from(info.clone()).is_err());
        let malformed = Zeroizing::new(info.to_pem(pkcs8::LineEnding::LF).unwrap());
        assert!(matches!(
            keyfile::decode(&malformed),
            Err(KeyFileError::InvalidFormat)
        ));
    }
}
