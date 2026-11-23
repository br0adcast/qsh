//! Runtime-generated RSA fixtures; no private material is printed.
use rsa::pkcs1::EncodeRsaPrivateKey;
use ssh_key::{Algorithm, HashAlg};
use sshauth::{
    keyfile::{self, KeyFileError},
    prepared_key::{PreparedKey, RsaDigest},
};
use zeroize::Zeroizing;

fn generate(bits: usize, exponent: u64) -> rsa::PrivateKey {
    rsa::PrivateKey::new_with_exp(
        &mut ssh_key::getrandom::SysRng,
        bits,
        rsa::BoxedUint::from(exponent),
    )
    .unwrap()
}

fn check(bits: usize, exponent: u64) {
    let generated = generate(bits, exponent);
    let pem = generated.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let key = keyfile::decode(&pem).unwrap().into_prepared(None).unwrap();
    for (digest, expected) in [
        (RsaDigest::Sha1, None),
        (RsaDigest::Sha256, Some(HashAlg::Sha256)),
        (RsaDigest::Sha512, Some(HashAlg::Sha512)),
    ] {
        let signature = key.sign(b"generated RSA fixture", digest).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: expected });
        signature::Verifier::verify(key.public_key(), b"generated RSA fixture", &signature)
            .unwrap();
        assert!(
            signature::Verifier::verify(key.public_key(), b"changed fixture", &signature).is_err()
        );
        let mut changed = signature.as_bytes().to_vec();
        changed[0] ^= 1;
        let changed = ssh_key::Signature::new(signature.algorithm(), changed).unwrap();
        assert!(
            signature::Verifier::verify(key.public_key(), b"generated RSA fixture", &changed)
                .is_err()
        );
    }
}

#[test]
fn rsa_preserves_sha1_sha256_sha512_and_small_exponents() {
    for exponent in [3, 65537] {
        check(2048, exponent);
    }
}

#[test]
#[ignore = "explicit generated large-key qualification"]
fn rsa_large_key_envelope() {
    for bits in [1024, 4096] {
        for exponent in [3, 65537] {
            check(bits, exponent);
        }
    }
    // Generating an 8192-bit key in pure Rust takes minutes on a CI runner;
    // one is enough to cover the widest accepted size.
    check(8192, 65537);
}

/// A multiprime PKCS#1 container (version 1, with OtherPrimeInfos) is refused
/// by the shared key formats before any arithmetic: accepted formats keep the
/// two-prime restriction. Its components come from a real two-prime key, so
/// only the container's structure makes it multiprime.
#[test]
fn rsa_rejects_a_multiprime_container() {
    use pkcs8::{der::EncodePem, LineEnding};
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let key = generate(1024, 65537);
    let bytes = |value: &rsa::BoxedUint| value.to_be_bytes().into_vec();
    let trimmed = |raw: Vec<u8>| {
        let first = raw.iter().position(|&b| b != 0).unwrap_or(raw.len() - 1);
        raw[first..].to_vec()
    };
    let (n, e, d) = (
        trimmed(bytes(key.n())),
        trimmed(bytes(key.e())),
        trimmed(bytes(key.d())),
    );
    let primes: Vec<Vec<u8>> = key.primes().iter().map(|p| trimmed(bytes(p))).collect();
    fn uint(raw: &[u8]) -> rsa::pkcs1::UintRef<'_> {
        rsa::pkcs1::UintRef::new(raw).unwrap()
    }
    let container = rsa::pkcs1::RsaPrivateKey {
        modulus: uint(&n),
        public_exponent: uint(&e),
        private_exponent: uint(&d),
        prime1: uint(&primes[0]),
        prime2: uint(&primes[1]),
        exponent1: uint(&d),
        exponent2: uint(&d),
        coefficient: uint(&primes[0]),
        other_prime_infos: Some(vec![rsa::pkcs1::OtherPrimeInfo {
            prime: uint(&primes[1]),
            exponent: uint(&d),
            coefficient: uint(&primes[0]),
        }]),
    };
    assert_eq!(container.version(), rsa::pkcs1::Version::Multi);
    let pem = Zeroizing::new(container.to_pem(LineEnding::LF).unwrap());
    assert!(matches!(
        keyfile::decode(&pem),
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
fn rsa_preserves_rfc5958_public_field_and_algorithm_parameter_policy() {
    use pkcs8::der::{asn1::BitStringRef, Decode, EncodePem};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::EncodePrivateKey;
    let owner = generate(2048, 65537);
    let public = owner.to_public_key().to_pkcs1_der().unwrap();
    let der = owner.to_pkcs8_der().unwrap();
    let mut info = pkcs8::PrivateKeyInfoRef::from_der(der.as_bytes()).unwrap();
    info.public_key = Some(BitStringRef::from_bytes(public.as_bytes()).unwrap());
    // The previous shared decoder accepts RFC5958's optional public field.
    assert!(rsa::PrivateKey::try_from(info.clone()).is_ok());
    let pem = Zeroizing::new(info.to_pem(pkcs8::LineEnding::LF).unwrap());
    let key = keyfile::decode(&pem)
        .expect("preserve accepted RFC5958 wrapper")
        .into_prepared(None)
        .unwrap();
    let signed = key.sign(b"RFC5958 fixture", RsaDigest::Sha512).unwrap();
    signature::Verifier::verify(key.public_key(), b"RFC5958 fixture", &signed).unwrap();

    // rsaEncryption requires explicit NULL in the shared parser; the key
    // decoder must not silently expand that outer-wrapper acceptance policy.
    info.public_key = None;
    for parameters in [
        None,
        Some(pkcs8::der::asn1::AnyRef::new(pkcs8::der::Tag::OctetString, b"generated").unwrap()),
    ] {
        info.algorithm.parameters = parameters;
        assert!(rsa::PrivateKey::try_from(info.clone()).is_err());
        let malformed = Zeroizing::new(info.to_pem(pkcs8::LineEnding::LF).unwrap());
        assert!(matches!(
            keyfile::decode(&malformed),
            Err(KeyFileError::InvalidFormat)
        ));
    }
}
