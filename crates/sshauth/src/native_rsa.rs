//! Owned native RSA. No private key serialization or application CRT operations.
use crate::{keyfile::KeyFileError, prepared_key::RsaDigest};
use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa, RsaPrivateKeyBuilder},
    sign::Signer,
};
use ssh_key::{
    private::RsaKeypair,
    public::{KeyData, RsaPublicKey},
    Algorithm, Mpint, PublicKey, Signature,
};

type Result<T> = std::result::Result<T, KeyFileError>;

pub(crate) struct NativeRsa {
    key: PKey<Private>,
    public: PublicKey,
    #[cfg(test)]
    pub(crate) probe: std::sync::Arc<crate::sign_file::NativeProbe>,
}

impl NativeRsa {
    pub(crate) fn from_components(pair: &RsaKeypair, public: PublicKey) -> Result<Self> {
        let rsa = RsaPrivateKeyBuilder::new(
            BigNum::from_slice(positive(pair.public().n())?).map_err(native_error)?,
            BigNum::from_slice(positive(pair.public().e())?).map_err(native_error)?,
            secret(pair.private().d())?,
        )
        .map_err(native_error)?
        .set_factors(secret(pair.private().p())?, secret(pair.private().q())?)
        .map_err(native_error)?
        .build();
        Self::validated(rsa, Some(public))
    }

    pub(crate) fn from_pkcs1(bytes: &[u8]) -> Result<Self> {
        two_prime(bytes)?;
        Self::validated(
            Rsa::private_key_from_der(bytes).map_err(native_error)?,
            None,
        )
    }

    pub(crate) fn from_pkcs8(bytes: &[u8], inner: &[u8]) -> Result<Self> {
        two_prime(inner)?;
        let key = PKey::private_key_from_pkcs8(bytes).map_err(native_error)?;
        Self::validated(key.rsa().map_err(native_error)?, None)
    }

    fn validated(rsa: Rsa<Private>, public: Option<PublicKey>) -> Result<Self> {
        #[cfg(test)]
        let probe = std::sync::Arc::new(crate::sign_file::NativeProbe::default());
        #[cfg(test)]
        probe
            .checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !rsa.check_key().map_err(native_error)? {
            return Err(KeyFileError::InvalidFormat);
        }
        let public = match public {
            Some(public) => public,
            None => PublicKey::new(
                KeyData::Rsa(
                    RsaPublicKey::new(
                        Mpint::from_positive_bytes(&rsa.e().to_vec()),
                        Mpint::from_positive_bytes(&rsa.n().to_vec()),
                    )
                    .map_err(|_| KeyFileError::InvalidFormat)?,
                ),
                "",
            ),
        };
        Ok(Self {
            key: PKey::from_rsa(rsa).map_err(native_error)?,
            public,
            #[cfg(test)]
            probe,
        })
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub(crate) fn sign(
        &self,
        message: &[u8],
        digest: RsaDigest,
        #[cfg(test)] probe: Option<&crate::sign_file::NativeProbe>,
    ) -> Result<Signature> {
        let (md, hash) = match digest {
            RsaDigest::Sha1 => (MessageDigest::sha1(), None),
            RsaDigest::Sha256 => (MessageDigest::sha256(), Some(ssh_key::HashAlg::Sha256)),
            RsaDigest::Sha512 => (MessageDigest::sha512(), Some(ssh_key::HashAlg::Sha512)),
        };
        #[cfg(test)]
        let probe = probe.or(Some(self.probe.as_ref()));
        #[cfg(test)]
        let md = if let Some(probe) = probe {
            use std::sync::atomic::Ordering;
            probe.calls.fetch_add(1, Ordering::SeqCst);
            if probe.fail.load(Ordering::SeqCst) {
                MessageDigest::null()
            } else {
                md
            }
        } else {
            md
        };
        let mut signer = Signer::new(md, &self.key).map_err(native_error)?;
        signer
            .set_rsa_padding(Padding::PKCS1)
            .map_err(native_error)?;
        signer.update(message).map_err(native_error)?;
        Signature::new(
            Algorithm::Rsa { hash },
            signer.sign_to_vec().map_err(native_error)?,
        )
        .map_err(|_| KeyFileError::NativeOperation)
    }
}

fn native_error(_: openssl::error::ErrorStack) -> KeyFileError {
    KeyFileError::NativeOperation
}
fn positive(value: &Mpint) -> Result<&[u8]> {
    value.as_positive_bytes().ok_or(KeyFileError::InvalidFormat)
}
fn secret(value: &Mpint) -> Result<BigNum> {
    let mut number = BigNum::new_secure().map_err(native_error)?;
    number
        .copy_from_slice(positive(value)?)
        .map_err(native_error)?;
    Ok(number)
}

// Structural inspection only: fixed borrowed INTEGERs avoid allocating an
// OtherPrimeInfos vector for rejected multiprime keys. All mathematics and
// private decoding are delegated to the native backend.
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
