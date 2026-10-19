//! A validated, owned local signing key. RSA never returns to an upstream
//! private-key representation after native preparation.
use crate::{keyfile::KeyFileError, native_rsa::NativeRsa};
use ssh_key::{PrivateKey, PublicKey, Signature};

/// SSH may negotiate legacy SHA-1. QSH callers explicitly choose SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaDigest {
    Sha1,
    Sha256,
    Sha512,
}

pub struct PreparedKey {
    inner: Inner,
}
enum Inner {
    Rsa(NativeRsa),
    Other(Box<PrivateKey>),
}
impl std::fmt::Debug for PreparedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedKey")
            .field("algorithm", &self.public_key().algorithm())
            .finish_non_exhaustive()
    }
}
impl PreparedKey {
    pub fn from_key(key: PrivateKey) -> Result<Self, KeyFileError> {
        if key.is_encrypted() {
            return Err(KeyFileError::PassphraseRequired);
        }
        let inner = if let Some(pair) = key.key_data().rsa() {
            Inner::Rsa(NativeRsa::from_components(pair, key.public_key().clone())?)
        } else {
            Inner::Other(Box::new(key))
        };
        Ok(Self { inner })
    }
    pub(crate) fn from_pkcs1(bytes: &[u8]) -> Result<Self, KeyFileError> {
        Ok(Self {
            inner: Inner::Rsa(NativeRsa::from_pkcs1(bytes)?),
        })
    }
    pub(crate) fn from_pkcs8(bytes: &[u8], inner: &[u8]) -> Result<Self, KeyFileError> {
        Ok(Self {
            inner: Inner::Rsa(NativeRsa::from_pkcs8(bytes, inner)?),
        })
    }
    #[cfg(test)]
    pub(crate) fn native_probe(&self) -> Option<&std::sync::Arc<crate::sign_file::NativeProbe>> {
        match &self.inner {
            Inner::Rsa(key) => Some(&key.probe),
            Inner::Other(_) => None,
        }
    }
    pub fn public_key(&self) -> &PublicKey {
        match &self.inner {
            Inner::Rsa(key) => key.public_key(),
            Inner::Other(key) => key.public_key(),
        }
    }
    pub fn sign(&self, message: &[u8], digest: RsaDigest) -> Result<Signature, KeyFileError> {
        self.sign_inner(
            message,
            digest,
            #[cfg(test)]
            None,
        )
    }
    pub(crate) fn sign_inner(
        &self,
        message: &[u8],
        digest: RsaDigest,
        #[cfg(test)] probe: Option<&crate::sign_file::NativeProbe>,
    ) -> Result<Signature, KeyFileError> {
        match &self.inner {
            Inner::Rsa(key) => key.sign(
                message,
                digest,
                #[cfg(test)]
                probe,
            ),
            Inner::Other(key) => signature::Signer::try_sign(key.as_ref(), message)
                .map_err(|_| KeyFileError::InvalidFormat),
        }
    }
}
