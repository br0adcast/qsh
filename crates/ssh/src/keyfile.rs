//! Private key files, and a signer that asks for a key's passphrase only
//! when the server has said it would take the key.

use std::path::Path;

use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_encoding::Encode;
use russh::keys::{HashAlg, PrivateKey};
use sshauth::{
    keyfile::DecodedKey,
    prepared_key::{PreparedKey, RsaDigest},
};

use crate::auth::{PromptClock, SignError};
use crate::AuthPrompter;

/// How many times a wrong passphrase may be typed before the key is given up.
const PASSPHRASE_TRIES: usize = 3;

/// Why an encrypted PEM key is skipped, and how to make it usable.
#[cfg(test)]
const ENCRYPTED_PEM: &str = "encrypted PEM keys are not supported; convert with ssh-keygen -p";

/// Reads a private key file: OpenSSH format, encrypted or not, or an
/// unencrypted PEM / PKCS#8 key. An encrypted OpenSSH key stays encrypted;
/// its public half is readable as it is. An encrypted PEM key (legacy
/// `Proc-Type: 4,ENCRYPTED` or PKCS#8 `ENCRYPTED PRIVATE KEY`) has no
/// public half to offer before its passphrase, and is not decoded here.
pub(crate) fn read(path: &Path) -> Result<DecodedKey, String> {
    let text = sshauth::keyfile::read_text(path).map_err(|e| e.to_string())?;
    decode(&text)
}

pub(crate) fn decode(text: &str) -> Result<DecodedKey, String> {
    match sshauth::keyfile::decode(text) {
        Ok(key) => Ok(key),
        Err(sshauth::keyfile::KeyFileError::ExplicitEcParameters) => {
            // This disposition positively identifies the rare SEC1 container.
            // Use the same bytes; rereading the path could change the format
            // between classification and the upstream decoder.
            russh::keys::decode_secret_key(text, None)
                .map_err(|_| "invalid explicit-parameter EC private key".to_owned())
                .and_then(|key| DecodedKey::from_key(key).map_err(|e| e.to_string()))
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Signs with an encrypted key, asking its passphrase at the moment russh
/// asks for the signature -- which it does only after the server's PK_OK.
///
/// Missing or exhausted passphrases send an empty signature, preserving the
/// existing rejected-attempt flow. A local preparation, signing or worker
/// failure terminates authentication after PK_OK; it must not select another
/// identity after the server has accepted this one.
pub(crate) struct LazyKeySigner<'a> {
    pub path: &'a Path,
    /// Still encrypted; decrypted copies live only inside `auth_sign`.
    pub key: &'a PrivateKey,
    pub prompter: &'a dyn AuthPrompter,
    pub clock: &'a PromptClock,
    /// Why no signature was made, if none was.
    pub gave_up: Option<String>,
}

impl russh::Signer for LazyKeySigner<'_> {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        for _ in 0..PASSPHRASE_TRIES {
            let Some(pass) = self.clock.ask(|| self.prompter.passphrase(self.path)) else {
                self.gave_up = Some(format!("{}: no passphrase given", self.path.display()));
                return Ok(append_signature(to_sign, &[]));
            };
            let encrypted = self.key.clone();
            let data = to_sign.clone();
            let result = crate::crypto_worker::run(move || {
                let key = encrypted
                    .decrypt(pass.as_bytes())
                    .map_err(|_| sshauth::keyfile::KeyFileError::DecryptionFailed)?;
                let key = PreparedKey::from_key(key)?;
                sign_with_hash_alg(&key, hash_alg, &data)
                    .map_err(|_| sshauth::keyfile::KeyFileError::NativeOperation)
            })
            .await
            .map_err(SignError::from)?;
            match result {
                Ok(blob) => return Ok(append_signature(to_sign, &blob)),
                Err(sshauth::keyfile::KeyFileError::DecryptionFailed) => continue,
                Err(error) => {
                    return Err(SignError::Signer(format!(
                        "{}: could not sign: {error}",
                        self.path.display()
                    )));
                }
            }
        }
        self.gave_up = Some(format!("{}: wrong passphrase", self.path.display()));
        Ok(append_signature(to_sign, &[]))
    }
}

/// `to_sign` with `string(blob)` appended, the way russh wants it back.
pub(crate) fn append_signature(mut to_sign: Vec<u8>, blob: &[u8]) -> Vec<u8> {
    to_sign.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    to_sign.extend_from_slice(blob);
    to_sign
}

/// The encoded SSH signature of `data`, as russh makes it for a key it
/// holds (its own helper is private): RSA with the negotiated hash, other
/// types as they are.
pub(crate) fn sign_with_hash_alg(
    key: &PreparedKey,
    hash_alg: Option<HashAlg>,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let digest = match hash_alg {
        None => RsaDigest::Sha1,
        Some(HashAlg::Sha256) => RsaDigest::Sha256,
        Some(HashAlg::Sha512) => RsaDigest::Sha512,
        Some(_) => return Err("unsupported RSA digest".into()),
    };
    let signature = key.sign(data, digest).map_err(|e| e.to_string())?;
    signature.encode_vec().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_read_uses_the_shared_input_limit() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![b'x'; 1024 * 1024 + 1]).unwrap();
        let error = read(file.path()).unwrap_err();
        assert!(error.contains("1 MiB"), "{error}");
        assert!(!error.contains("xxxx"));
    }

    #[test]
    fn a_signature_is_appended_as_an_ssh_string() {
        assert_eq!(
            append_signature(vec![9], &[1, 2]),
            vec![9, 0, 0, 0, 2, 1, 2]
        );
    }

    #[test]
    fn no_signature_is_appended_as_an_empty_string() {
        assert_eq!(append_signature(vec![9], &[]), vec![9, 0, 0, 0, 0]);
    }

    /// `ssh-keygen -m <format>` writes a key locked with a passphrase.
    fn locked_pem(format: &str, dir: &Path) -> std::path::PathBuf {
        let path = dir.join(format!("key_{format}"));
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ecdsa", "-m", format, "-N", "passw0rd", "-f"])
            .arg(&path)
            .status()
            .expect("ssh-keygen")
            .success();
        assert!(ok, "ssh-keygen failed");
        path
    }

    /// Legacy PEM (`Proc-Type: 4,ENCRYPTED`) and encrypted PKCS#8 are not
    /// decoded here; the reason says how to make the key usable.
    #[test]
    fn an_encrypted_pem_key_is_refused_with_a_way_out() {
        let dir = tempfile::tempdir().unwrap();
        for format in ["PEM", "PKCS8"] {
            let path = locked_pem(format, dir.path());
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains("Proc-Type: 4,ENCRYPTED")
                    || text.contains("BEGIN ENCRYPTED PRIVATE KEY"),
                "{format}: not an encrypted PEM file"
            );
            match read(&path) {
                Err(why) => assert_eq!(why, ENCRYPTED_PEM, "{format}"),
                Ok(_) => panic!("{format}: an encrypted PEM key was read"),
            }
        }
    }
}
