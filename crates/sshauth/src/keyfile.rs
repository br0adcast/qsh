//! Private-file containers shared by QSH signing and SSH authentication.
//! Parsing never prompts or decrypts an encrypted OpenSSH key.

use std::{fmt, io, path::Path};

use pkcs8::{AssociatedOid, DecodePrivateKey, SecretDocument};
use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData},
    PrivateKey,
};
use zeroize::Zeroizing;

/// Safe classifications for a private-file failure. No variant retains input
/// bytes, a passphrase, or a decoder message that may quote private material.
#[derive(Debug)]
pub enum KeyFileError {
    Io(io::Error),
    InvalidFormat,
    UnsupportedFormat,
    /// A positively identified SEC1 container requiring the existing SSH-only
    /// upstream explicit-domain-parameter decoder. Never a general parse retry.
    ExplicitEcParameters,
    UnsupportedEncryptedFormat,
    UnsupportedEncryptedPpk,
    PassphraseRequired,
    DecryptionFailed,
    NativeOperation,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "could not read private key: {error}"),
            Self::InvalidFormat => f.write_str("invalid private-key file"),
            Self::UnsupportedFormat => f.write_str("unsupported private-key format or algorithm"),
            Self::ExplicitEcParameters => {
                f.write_str("explicit EC parameters require the SSH key decoder")
            }
            Self::UnsupportedEncryptedFormat => {
                f.write_str("encrypted PEM keys are not supported; convert with ssh-keygen -p")
            }
            Self::UnsupportedEncryptedPpk => {
                f.write_str("encrypted PPK files are not supported; convert to OpenSSH format")
            }
            Self::PassphraseRequired => f.write_str("key is encrypted and needs a passphrase"),
            Self::NativeOperation => f.write_str("native private-key operation failed"),
            Self::DecryptionFailed => {
                f.write_str("could not decrypt private key with this passphrase")
            }
        }
    }
}

impl std::error::Error for KeyFileError {}

/// A file retains either its locked OpenSSH representation or its prepared
/// signing owner. Native RSA is never projected back into secret SSH components.
#[derive(Debug)]
pub enum DecodedKey {
    Locked(Box<PrivateKey>),
    Prepared(crate::prepared_key::PreparedKey),
}
impl DecodedKey {
    pub fn from_key(key: PrivateKey) -> Result<Self, KeyFileError> {
        if key.is_encrypted() {
            Ok(Self::Locked(Box::new(key)))
        } else {
            crate::prepared_key::PreparedKey::from_key(key).map(Self::Prepared)
        }
    }
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Locked(_))
    }
    pub fn public_key(&self) -> &ssh_key::PublicKey {
        match self {
            Self::Locked(key) => key.public_key(),
            Self::Prepared(key) => key.public_key(),
        }
    }
    pub fn into_prepared(
        self,
        phrase: Option<&str>,
    ) -> Result<crate::prepared_key::PreparedKey, KeyFileError> {
        match self {
            Self::Prepared(key) => Ok(key),
            Self::Locked(key) => crate::prepared_key::PreparedKey::from_key(
                key.decrypt(phrase.ok_or(KeyFileError::PassphraseRequired)?)
                    .map_err(|_| KeyFileError::DecryptionFailed)?,
            ),
        }
    }
}

/// Read once into storage that is cleared when parsing finishes.
pub fn read(path: &Path) -> Result<DecodedKey, KeyFileError> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(KeyFileError::Io)?);
    decode(&text)
}

/// Decode a supported container, retaining an OpenSSH key's encryption state.
pub fn decode(text: &str) -> Result<DecodedKey, KeyFileError> {
    let text = text.trim();
    let first = text.lines().next().ok_or(KeyFileError::InvalidFormat)?;
    if first.starts_with("PuTTY-User-Key-File-") {
        // PPK has no public-only encrypted representation in ssh-key. Retain
        // plaintext support without adding a pre-offer passphrase request.
        if text
            .lines()
            .take_while(|line| !line.starts_with("Public-Lines:"))
            .filter_map(|line| line.strip_prefix("Encryption:"))
            .any(|encryption| encryption.trim() != "none")
        {
            return Err(KeyFileError::UnsupportedEncryptedPpk);
        }
        return DecodedKey::from_key(
            PrivateKey::from_ppk(text, None).map_err(|_| KeyFileError::InvalidFormat)?,
        );
    }
    // OpenSSL exports can carry Bag Attributes before the PEM boundary. Let
    // the upstream grammar locate that boundary, while retaining exactly one
    // complete container and checking encryption headers only inside it.
    let label =
        pkcs8::der::pem::decode_label(text.as_bytes()).map_err(|_| KeyFileError::InvalidFormat)?;
    let footer = format!("-----END {label}-----");
    if text.lines().last() != Some(footer.as_str())
        || text
            .lines()
            .filter(|line| line.starts_with("-----BEGIN "))
            .count()
            != 1
        || text
            .lines()
            .filter(|line| line.starts_with("-----END "))
            .count()
            != 1
    {
        return Err(KeyFileError::InvalidFormat);
    }
    if label == "ENCRYPTED PRIVATE KEY" {
        return Err(KeyFileError::UnsupportedEncryptedFormat);
    }
    // Traditional PEM headers precede the base64 body. A comment or arbitrary
    // substring elsewhere must not turn malformed input into a password request.
    if matches!(label, "RSA PRIVATE KEY" | "EC PRIVATE KEY") {
        let body = text
            .lines()
            .skip_while(|line| !line.starts_with("-----BEGIN "))
            .skip(1);
        for line in body {
            if line.trim().is_empty() {
                continue;
            }
            if line.starts_with("Proc-Type:") || line.starts_with("DEK-Info:") {
                return Err(KeyFileError::UnsupportedEncryptedFormat);
            }
            break;
        }
    }
    if label == "OPENSSH PRIVATE KEY" {
        return DecodedKey::from_key(
            PrivateKey::from_openssh(text).map_err(|_| KeyFileError::InvalidFormat)?,
        );
    }
    if !matches!(label, "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "PRIVATE KEY") {
        return Err(KeyFileError::UnsupportedFormat);
    }
    // Existing SSH writers use MIME's 76-column CRLF wrapping as well as
    // PEM's usual 64 columns. Let the upstream PEM decoder determine wrapping;
    // container labels and DER validation remain mandatory for both forms.
    let mut decoder = pkcs8::der::pem::Decoder::new_detect_wrap(text.as_bytes())
        .map_err(|_| KeyFileError::InvalidFormat)?;
    let mut bytes = Zeroizing::new(Vec::new());
    decoder
        .decode_to_end(&mut bytes)
        .map_err(|_| KeyFileError::InvalidFormat)?;
    if label == "RSA PRIVATE KEY" {
        return crate::prepared_key::PreparedKey::from_pkcs1(&bytes).map(DecodedKey::Prepared);
    }
    if label == "PRIVATE KEY" {
        use pkcs8::der::Decode;
        let info =
            pkcs8::PrivateKeyInfoRef::from_der(&bytes).map_err(|_| KeyFileError::InvalidFormat)?;
        if info.algorithm.oid == pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
            // Preserve the previous rsaEncryption AlgorithmIdentifier policy:
            // explicit NULL is required, even if the native decoder is lenient.
            if info.algorithm.parameters != Some(pkcs8::der::asn1::AnyRef::NULL) {
                return Err(KeyFileError::InvalidFormat);
            }
            return crate::prepared_key::PreparedKey::from_pkcs8(
                &bytes,
                info.private_key.as_bytes(),
            )
            .map(DecodedKey::Prepared);
        }
    }
    let doc =
        SecretDocument::try_from(bytes.as_slice()).map_err(|_| KeyFileError::InvalidFormat)?;
    let data = match label {
        "EC PRIVATE KEY" => {
            if explicit_ec_parameters(doc.as_bytes()).map_err(|_| KeyFileError::InvalidFormat)? {
                return Err(KeyFileError::ExplicitEcParameters);
            }
            let key = doc
                .decode_msg::<sec1::EcPrivateKey<'_>>()
                .map_err(|_| KeyFileError::InvalidFormat)?;
            let oid = key
                .parameters
                .and_then(|params| params.named_curve())
                .ok_or(KeyFileError::UnsupportedFormat)?;
            if oid == p256::NistP256::OID {
                let secret =
                    p256::SecretKey::try_from(key).map_err(|_| KeyFileError::InvalidFormat)?;
                p256_data(secret)
            } else if oid == p384::NistP384::OID {
                p384_data(p384::SecretKey::try_from(key).map_err(|_| KeyFileError::InvalidFormat)?)
            } else if oid == p521::NistP521::OID {
                p521_data(p521::SecretKey::try_from(key).map_err(|_| KeyFileError::InvalidFormat)?)
            } else {
                return Err(KeyFileError::UnsupportedFormat);
            }
        }
        "PRIVATE KEY" => {
            let info = doc
                .decode_msg::<pkcs8::PrivateKeyInfoRef<'_>>()
                .map_err(|_| KeyFileError::InvalidFormat)?;
            if info.algorithm.oid == ed25519_dalek::pkcs8::ALGORITHM_OID {
                let key = ed25519_dalek::SigningKey::from_pkcs8_der(doc.as_bytes())
                    .map_err(|_| KeyFileError::InvalidFormat)?;
                KeypairData::Ed25519(Ed25519Keypair::from(key))
            } else if info.algorithm.oid == sec1::ALGORITHM_OID {
                let oid = info
                    .algorithm
                    .parameters_oid()
                    .map_err(|_| KeyFileError::InvalidFormat)?;
                if oid == p256::NistP256::OID {
                    p256_data(
                        p256::SecretKey::try_from(info).map_err(|_| KeyFileError::InvalidFormat)?,
                    )
                } else if oid == p384::NistP384::OID {
                    p384_data(
                        p384::SecretKey::try_from(info).map_err(|_| KeyFileError::InvalidFormat)?,
                    )
                } else if oid == p521::NistP521::OID {
                    p521_data(
                        p521::SecretKey::try_from(info).map_err(|_| KeyFileError::InvalidFormat)?,
                    )
                } else {
                    return Err(KeyFileError::UnsupportedFormat);
                }
            } else {
                return Err(KeyFileError::UnsupportedFormat);
            }
        }
        _ => unreachable!("container labels were checked before decoding"),
    };
    DecodedKey::from_key(PrivateKey::new(data, "").map_err(|_| KeyFileError::InvalidFormat)?)
}

fn p256_data(key: p256::SecretKey) -> KeypairData {
    KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
        public: key.public_key().into(),
        private: key.into(),
    })
}

fn p384_data(key: p384::SecretKey) -> KeypairData {
    KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
        public: key.public_key().into(),
        private: key.into(),
    })
}

fn p521_data(key: p521::SecretKey) -> KeypairData {
    KeypairData::Ecdsa(EcdsaKeypair::NistP521 {
        public: key.public_key().into(),
        private: key.into(),
    })
}

/// Inspect only the SEC1 envelope using the upstream DER reader. Curve-domain
/// interpretation and all key mathematics remain in the existing SSH decoder.
fn explicit_ec_parameters(bytes: &[u8]) -> Result<bool, pkcs8::der::Error> {
    use pkcs8::der::{
        asn1::{AnyRef, BitStringRef, ContextSpecific, OctetStringRef},
        Reader, SliceReader, Tag, TagNumber, Tagged,
    };
    let mut reader = SliceReader::new(bytes)?;
    let explicit = reader.sequence(|fields| -> Result<bool, pkcs8::der::Error> {
        let version: u8 = fields.decode()?;
        if version != 1 {
            return Err(Tag::Integer.value_error().into());
        }
        let _: &OctetStringRef = fields.decode()?;
        let parameters = ContextSpecific::<AnyRef<'_>>::decode_explicit(fields, TagNumber(0))?;
        let public = ContextSpecific::<BitStringRef<'_>>::decode_explicit(fields, TagNumber(1))?;
        if public.is_some_and(|value| value.value.as_bytes().is_none()) {
            return Err(Tag::BitString.value_error().into());
        }
        Ok(parameters.is_some_and(|value| value.value.tag() == Tag::Sequence))
    })?;
    reader.finish()?;
    Ok(explicit)
}
