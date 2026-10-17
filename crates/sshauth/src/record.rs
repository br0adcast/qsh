//! Turning SSH keys and signatures into the bytes the AUTH record carries,
//! and back. The wire encodings are the standard SSH ones, so a public key
//! here is byte-identical to what sits base64-encoded in `authorized_keys`.

use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{PublicKey, Signature};
use transport::auth::AuthError;

/// The SSH wire encoding of a public key (the blob behind the base64 in
/// `authorized_keys`).
pub fn encode_public_key(key: &PublicKey) -> Result<Vec<u8>, AuthError> {
    let mut out = Vec::new();
    key.key_data()
        .encode(&mut out)
        .map_err(|e| AuthError::Backend(format!("encoding a public key: {e}")))?;
    Ok(out)
}

/// Parse a public key from its SSH wire encoding, strictly: any bytes left
/// over after a complete key are rejected rather than silently ignored, the
/// same way [`transport::auth::parse_auth_record`] rejects trailing bytes
/// after a complete record. Malformed input is a bad record, not a backend
/// failure: it came off the network.
pub fn decode_public_key(bytes: &[u8]) -> Result<PublicKey, AuthError> {
    PublicKey::from_bytes(bytes).map_err(|_| AuthError::BadRecord)
}

/// The SSH wire encoding of a signature: it names its own algorithm, which is
/// why the record needs no separate algorithm field.
pub fn encode_signature(sig: &Signature) -> Result<Vec<u8>, AuthError> {
    let mut out = Vec::new();
    sig.encode(&mut out)
        .map_err(|e| AuthError::Backend(format!("encoding a signature: {e}")))?;
    Ok(out)
}

/// Parse a signature from its SSH wire encoding, strictly: any trailing
/// bytes after a complete signature are rejected, for the same reason
/// [`decode_public_key`] rejects them. `Signature::decode` alone stops as
/// soon as it has read a complete signature and does not notice padding
/// appended after it, so the reader is explicitly required to be exhausted.
pub fn decode_signature(bytes: &[u8]) -> Result<Signature, AuthError> {
    let mut reader = bytes;
    let sig = Signature::decode(&mut reader).map_err(|_| AuthError::BadRecord)?;
    reader.finish(sig).map_err(|_| AuthError::BadRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};

    fn key() -> PrivateKey {
        PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen")
    }

    #[test]
    fn a_public_key_round_trips() {
        let k = key();
        let bytes = encode_public_key(k.public_key()).expect("encode");
        let decoded = decode_public_key(&bytes).expect("decode");
        assert_eq!(decoded.key_data(), k.public_key().key_data());
    }

    #[test]
    fn a_signature_round_trips() {
        let k = key();
        let sig = signature::Signer::try_sign(&k, b"anything").expect("sign");
        let bytes = encode_signature(&sig).expect("encode");
        let decoded = decode_signature(&bytes).expect("decode");
        assert_eq!(decoded, sig);
    }

    /// A peer that pads a length field so the extra bytes still fall inside
    /// it would otherwise get away with it (many distinct byte strings all
    /// decoding to the same key), and this crate's own `verify()` would
    /// still accept it since it never re-encodes to compare. The decoder
    /// itself is the only place this can be caught.
    #[test]
    fn a_public_key_with_a_trailing_byte_is_rejected() {
        let k = key();
        let mut bytes = encode_public_key(k.public_key()).expect("encode");
        bytes.push(0xFF);
        assert_eq!(decode_public_key(&bytes), Err(AuthError::BadRecord));
    }

    #[test]
    fn a_signature_with_a_trailing_byte_is_rejected() {
        let k = key();
        let sig = signature::Signer::try_sign(&k, b"anything").expect("sign");
        let mut bytes = encode_signature(&sig).expect("encode");
        bytes.push(0xFF);
        assert_eq!(decode_signature(&bytes), Err(AuthError::BadRecord));
    }
}
