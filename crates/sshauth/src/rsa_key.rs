//! Owned RSA private keys on the pure-Rust `rsa` crate. One preparation per
//! key: components are validated and the CRT values precomputed once, and
//! every signature is blinded. No application CRT arithmetic and no private
//! key serialization.
use crate::{keyfile::KeyFileError, prepared_key::RsaDigest};
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePrivateKey,
    traits::PublicKeyParts, BoxedUint,
};
use sha2::Digest;
use ssh_key::{
    private::RsaKeypair,
    public::{KeyData, RsaPublicKey},
    Algorithm, Mpint, PublicKey, Signature,
};

type Result<T> = std::result::Result<T, KeyFileError>;

pub(crate) struct OwnedRsa {
    key: rsa::PrivateKey,
    public: PublicKey,
    #[cfg(test)]
    pub(crate) probe: std::sync::Arc<crate::sign_file::RsaProbe>,
}

impl OwnedRsa {
    /// From an OpenSSH or PPK key's components. Two balanced primes, as the
    /// crate's own PKCS#1 decoder requires; the modulus width bounds the rest.
    pub(crate) fn from_components(pair: &RsaKeypair, public: PublicKey) -> Result<Self> {
        let n = positive(pair.public().n())?;
        let bits = width(n)?;
        let key = rsa::PrivateKey::from_components(
            uint(n, bits)?,
            uint(
                positive(pair.public().e())?,
                width(positive(pair.public().e())?)?,
            )?,
            uint(positive(pair.private().d())?, bits)?,
            vec![
                uint(positive(pair.private().p())?, bits)?,
                uint(positive(pair.private().q())?, bits)?,
            ],
        )
        .map_err(|_| KeyFileError::InvalidFormat)?;
        Ok(Self::prepared(key, Some(public)))
    }

    pub(crate) fn from_pkcs1(bytes: &[u8]) -> Result<Self> {
        two_prime(bytes)?;
        let key =
            rsa::PrivateKey::from_pkcs1_der(bytes).map_err(|_| KeyFileError::InvalidFormat)?;
        Ok(Self::prepared(key, None))
    }

    pub(crate) fn from_pkcs8(bytes: &[u8], inner: &[u8]) -> Result<Self> {
        two_prime(inner)?;
        let key =
            rsa::PrivateKey::from_pkcs8_der(bytes).map_err(|_| KeyFileError::InvalidFormat)?;
        Ok(Self::prepared(key, None))
    }

    /// The crate validated the components and precomputed the CRT values
    /// when it built the key (`from_components`, which its decoders call).
    fn prepared(key: rsa::PrivateKey, public: Option<PublicKey>) -> Self {
        #[cfg(test)]
        let probe = std::sync::Arc::new(crate::sign_file::RsaProbe::default());
        #[cfg(test)]
        probe
            .checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let public = public.unwrap_or_else(|| {
            PublicKey::new(
                KeyData::Rsa(
                    RsaPublicKey::new(
                        Mpint::from_positive_bytes(&key.e().to_be_bytes()),
                        Mpint::from_positive_bytes(&key.n().to_be_bytes()),
                    )
                    .expect("a validated key's public parts encode"),
                ),
                "",
            )
        });
        Self {
            key,
            public,
            #[cfg(test)]
            probe,
        }
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub(crate) fn sign(
        &self,
        message: &[u8],
        digest: RsaDigest,
        #[cfg(test)] probe: Option<&crate::sign_file::RsaProbe>,
    ) -> Result<Signature> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            let probe = probe.unwrap_or(self.probe.as_ref());
            probe.calls.fetch_add(1, Ordering::SeqCst);
            if probe.fail.load(Ordering::SeqCst) {
                return Err(KeyFileError::KeyOperation);
            }
        }
        let (scheme, hashed, hash) = match digest {
            RsaDigest::Sha1 => (
                Pkcs1v15Sign::new::<sha1::Sha1>(),
                sha1::Sha1::digest(message).to_vec(),
                None,
            ),
            RsaDigest::Sha256 => (
                Pkcs1v15Sign::new::<sha2::Sha256>(),
                sha2::Sha256::digest(message).to_vec(),
                Some(ssh_key::HashAlg::Sha256),
            ),
            RsaDigest::Sha512 => (
                Pkcs1v15Sign::new::<sha2::Sha512>(),
                sha2::Sha512::digest(message).to_vec(),
                Some(ssh_key::HashAlg::Sha512),
            ),
        };
        let signed = self
            .key
            .sign_with_rng(&mut ssh_key::getrandom::SysRng, scheme, &hashed)
            .map_err(|_| KeyFileError::KeyOperation)?;
        Signature::new(Algorithm::Rsa { hash }, signed).map_err(|_| KeyFileError::KeyOperation)
    }
}

fn positive(value: &Mpint) -> Result<&[u8]> {
    value.as_positive_bytes().ok_or(KeyFileError::InvalidFormat)
}
fn width(bytes: &[u8]) -> Result<u32> {
    u32::try_from(bytes.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .ok_or(KeyFileError::InvalidFormat)
}
fn uint(bytes: &[u8], bits: u32) -> Result<BoxedUint> {
    BoxedUint::from_be_slice(bytes, bits).map_err(|_| KeyFileError::InvalidFormat)
}

// Structural inspection only: fixed borrowed INTEGERs avoid allocating an
// OtherPrimeInfos vector for rejected multiprime keys.
fn two_prime(bytes: &[u8]) -> Result<()> {
    use pkcs8::der::{asn1::UintRef, Reader, SliceReader, Tag};
    let parse = || -> std::result::Result<(), pkcs8::der::Error> {
        let mut reader = SliceReader::new(bytes)?;
        reader.sequence(|fields| -> std::result::Result<(), pkcs8::der::Error> {
            let version: u8 = fields.decode()?;
            if version != 0 {
                return Err(Tag::Integer.value_error().into());
            }
            for _ in 0..8 {
                let _: UintRef = fields.decode()?;
            }
            Ok(())
        })?;
        reader.finish()
    };
    parse().map_err(|_| KeyFileError::InvalidFormat)
}
