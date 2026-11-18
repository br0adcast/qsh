// qsh modification: omit fixed private-key cases; preserve generated and malformed cases.
use ssh_key::{Algorithm, PrivateKey};

use crate::keys::pkcs8::{decode_pkcs8, encode_pkcs8_encrypted};

use super::decode_secret_key;

#[test]
fn test_pkcs8_roundtrip() {
    let password = b"SomePassword";
    let original_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();

    let encrypted = encode_pkcs8_encrypted(password, 10, &original_key).unwrap();
    let decrypted = decode_pkcs8(&encrypted, Some(password)).unwrap();
    assert_eq!(decrypted, original_key);
}

#[test]
fn test_ec_malformed_der_returns_error() {
    // Completely invalid data — not valid SEC1 or PKCS#8
    let result = decode_secret_key("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----", None);
    assert!(result.is_err(), "Should fail on malformed DER");

    // Truncated SEC1 key
    let result = decode_secret_key("-----BEGIN EC PRIVATE KEY-----\nMIIBaAIBAQQg\n-----END EC PRIVATE KEY-----", None);
    assert!(result.is_err(), "Should fail on truncated key");
}
