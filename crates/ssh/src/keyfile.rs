//! Private key files, and a signer that asks for a key's passphrase only
//! when the server has said it would take the key.

use std::path::Path;

use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_encoding::Encode;
use russh::keys::{HashAlg, PrivateKey};
use zeroize::Zeroizing;

use crate::auth::{PromptClock, SignError};
use crate::AuthPrompter;

/// How many times a wrong passphrase may be typed before the key is given up.
const PASSPHRASE_TRIES: usize = 3;

/// Why an encrypted PEM key is skipped, and how to make it usable.
const ENCRYPTED_PEM: &str = "encrypted PEM keys are not supported; convert with ssh-keygen -p";

/// Reads a private key file: OpenSSH format, encrypted or not, or an
/// unencrypted PEM / PKCS#8 key. An encrypted OpenSSH key stays encrypted;
/// its public half is readable as it is. An encrypted PEM key (legacy
/// `Proc-Type: 4,ENCRYPTED` or PKCS#8 `ENCRYPTED PRIVATE KEY`) has no
/// public half to offer before its passphrase, and is not decoded here.
pub(crate) fn read(path: &Path) -> Result<PrivateKey, String> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| e.to_string())?);
    if text.contains("Proc-Type: 4,ENCRYPTED")
        || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    {
        return Err(ENCRYPTED_PEM.into());
    }
    match PrivateKey::from_openssh(text.as_bytes()) {
        Ok(key) => Ok(key),
        Err(_) => russh::keys::decode_secret_key(&text, None).map_err(|e| e.to_string()),
    }
}

/// Signs with an encrypted key, asking its passphrase at the moment russh
/// asks for the signature -- which it does only after the server's PK_OK.
///
/// A signature that cannot be made is sent empty: the server refuses it
/// like any other failed attempt and the login goes on. An error returned
/// from `auth_sign` would leave russh waiting for a signature that never
/// comes, and the next method would hang.
pub(crate) struct LazyKeySigner<'a> {
    pub path: &'a Path,
    /// Still encrypted; decrypted copies live only inside `auth_sign`.
    pub key: &'a PrivateKey,
    pub prompter: &'a dyn AuthPrompter,
    pub clock: &'a PromptClock,
    /// Why no signature was made, if none was.
    pub gave_up: Option<String>,
}

impl LazyKeySigner<'_> {
    fn sign(&self, hash_alg: Option<HashAlg>, data: &[u8]) -> Result<Vec<u8>, String> {
        for _ in 0..PASSPHRASE_TRIES {
            let Some(pass) = self.clock.ask(|| self.prompter.passphrase(self.path)) else {
                return Err(format!("{}: no passphrase given", self.path.display()));
            };
            // Zeroes itself when dropped, before this call returns.
            let Ok(key) = self.key.decrypt(pass.as_bytes()) else {
                continue;
            };
            return sign_with_hash_alg(&key, hash_alg, data)
                .map_err(|e| format!("{}: could not sign: {e}", self.path.display()));
        }
        Err(format!("{}: wrong passphrase", self.path.display()))
    }
}

impl russh::Signer for LazyKeySigner<'_> {
    type Error = SignError;

    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let blob = match self.sign(hash_alg, &to_sign) {
            Ok(blob) => blob,
            Err(why) => {
                self.gave_up = Some(why);
                Vec::new()
            }
        };
        std::future::ready(Ok(append_signature(to_sign, &blob)))
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
fn sign_with_hash_alg(
    key: &PrivateKey,
    hash_alg: Option<HashAlg>,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    use russh::keys::signature::Signer;
    let signature = match key.key_data() {
        russh::keys::ssh_key::private::KeypairData::Rsa(rsa) => (rsa, hash_alg).try_sign(data),
        keypair => keypair.try_sign(data),
    }
    .map_err(|e| e.to_string())?;
    signature.encode_vec().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
