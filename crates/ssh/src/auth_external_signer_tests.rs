use super::*;
use russh::Signer;
use ssh_key::{Algorithm, EcdsaCurve};
use sshauth::prepared_key::{PreparedKey, RsaDigest};

struct FixedSignature(Vec<u8>);
impl ExternalSigner for FixedSignature {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        Err("the bridge must use the already offered identity".into())
    }
    fn sign_ssh(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

fn generated(algorithm: Algorithm) -> PreparedKey {
    PreparedKey::from_key(
        ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            algorithm,
        )
        .unwrap(),
    )
    .unwrap()
}

async fn bridge(
    offered: &PublicKey,
    signer: &PreparedKey,
    hash: Option<HashAlg>,
    digest: RsaDigest,
) -> Result<Vec<u8>, SignError> {
    let signature = signer.sign(b"request", digest).unwrap();
    let blob = sshauth::record::encode_signature(&signature).unwrap();
    let mut bridge = SignerBridge(Arc::new(FixedSignature(blob)));
    bridge
        .auth_sign(&offered.clone().into(), hash, b"request".to_vec())
        .await
}

#[tokio::test]
async fn external_signer_rejects_valid_records_for_another_key_family_or_curve() {
    let p256 = generated(Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    });
    let p384 = generated(Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    });
    let ed = generated(Algorithm::Ed25519);
    for signer in [&p384, &ed] {
        let result = bridge(p256.public_key(), signer, None, RsaDigest::Sha512).await;
        assert!(
            matches!(result, Err(SignError::Signer(_))),
            "a mismatched algorithm was appended: {result:?}"
        );
    }
}

#[tokio::test]
async fn external_signer_preserves_matching_non_rsa_records() {
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
    ] {
        let key = generated(algorithm);
        let result = bridge(key.public_key(), &key, None, RsaDigest::Sha512)
            .await
            .unwrap();
        assert_eq!(&result[..7], b"request");
        let length = u32::from_be_bytes(result[7..11].try_into().unwrap()) as usize;
        assert_eq!(result.len(), 11 + length);
        assert_eq!(
            sshauth::record::decode_signature(&result[11..])
                .unwrap()
                .algorithm(),
            key.public_key().algorithm()
        );
    }
}

#[tokio::test]
async fn external_signer_requires_the_selected_rsa_signature_hash() {
    let key = generated(Algorithm::Rsa { hash: None });
    for (hash, matching) in [
        (None, RsaDigest::Sha1),
        (Some(HashAlg::Sha256), RsaDigest::Sha256),
        (Some(HashAlg::Sha512), RsaDigest::Sha512),
    ] {
        assert!(bridge(key.public_key(), &key, hash, matching).await.is_ok());
        for wrong in [RsaDigest::Sha1, RsaDigest::Sha256, RsaDigest::Sha512] {
            if wrong != matching {
                let result = bridge(key.public_key(), &key, hash, wrong).await;
                assert!(
                    matches!(result, Err(SignError::Signer(_))),
                    "wrong RSA hash was appended: {hash:?}/{wrong:?}"
                );
            }
        }
    }
}
