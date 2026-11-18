// qsh modification: caller-provided key documentation and fixture-free tests; see README.qsh.md.
//! Methods for opening SSH key files, decrypting caller-provided keys, and
//! communicating with SSH agents.
//!
//! Obtain encoded private-key material and any password from the caller:
//!
//! ```
//! use russh::keys::{decode_secret_key, Error, PrivateKey};
//!
//! fn parse_private_key(encoded: &str, password: Option<&str>) -> Result<PrivateKey, Error> {
//!     decode_secret_key(encoded, password)
//! }
//! ```

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::string::FromUtf8Error;

use aes::cipher::inout::PadError;
use data_encoding::BASE64_MIME;
use thiserror::Error;

use crate::helpers::EncodedExt;

pub mod key;
pub use key::PrivateKeyWithHashAlg;

mod format;
pub use format::*;
// Reexports
pub use signature;
pub use ssh_encoding;
pub use ssh_key::{self, Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey};

/// OpenSSH agent protocol implementation
pub mod agent;

#[cfg(not(target_arch = "wasm32"))]
pub mod known_hosts;

#[cfg(not(target_arch = "wasm32"))]
pub use known_hosts::{check_known_hosts, check_known_hosts_path};

pub use crate::cert::PublicKeyOrCertificate;

#[derive(Debug, Error)]
pub enum Error {
    /// The key could not be read, for an unknown reason
    #[error("Could not read key")]
    CouldNotReadKey,
    /// The type of the key is unsupported
    #[error("Unsupported key type {}", key_type_string)]
    UnsupportedKeyType {
        key_type_string: String,
        key_type_raw: Vec<u8>,
    },
    /// The type of the key is unsupported
    #[error("Invalid Ed25519 key data")]
    Ed25519KeyError(#[from] ed25519_dalek::SignatureError),
    /// The type of the key is unsupported
    #[error("Invalid ECDSA key data")]
    EcdsaKeyError(#[from] p256::elliptic_curve::Error),
    /// The key is encrypted (should supply a password?)
    #[error("The key is encrypted")]
    KeyIsEncrypted,
    /// The key contents are inconsistent
    #[error("The key is corrupt")]
    KeyIsCorrupt,
    /// Home directory could not be found
    #[error("No home directory found")]
    NoHomeDir,
    /// The server key has changed
    #[error("The server key changed at line {}", line)]
    KeyChanged { line: usize },
    /// The key uses an unsupported algorithm
    #[error("Unknown key algorithm: {0}")]
    UnknownAlgorithm(::pkcs8::ObjectIdentifier),
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// Unknown signature type
    #[error("Unknown signature type: {}", sig_type)]
    UnknownSignatureType { sig_type: String },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid parameters")]
    InvalidParameters,
    /// Agent protocol error
    #[error("Agent protocol error")]
    AgentProtocolError,
    #[error("Agent failure")]
    AgentFailure,
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[cfg(feature = "rsa")]
    #[error("Rsa: {0}")]
    Rsa(#[from] rsa::Error),

    #[error(transparent)]
    Pad(#[from] PadError),

    #[error(transparent)]
    Unpad(#[from] aes::cipher::block_padding::Error),

    #[error("Base64 decoding error: {0}")]
    Decode(#[from] data_encoding::DecodeError),
    #[error("Der: {0}")]
    Der(#[from] der::Error),
    #[error("Spki: {0}")]
    Spki(#[from] spki::Error),
    #[cfg(feature = "rsa")]
    #[error("Pkcs1: {0}")]
    Pkcs1(#[from] pkcs1::Error),
    #[error("Pkcs8: {0}")]
    Pkcs8(#[from] ::pkcs8::Error),
    #[error("Sec1: {0}")]
    Sec1(#[from] sec1::Error),

    #[error("SshKey: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("SshEncoding: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("Environment variable `{0}` not found")]
    EnvVar(&'static str),
    #[error(
        "Unable to connect to ssh-agent. The environment variable `SSH_AUTH_SOCK` was set, but it \
         points to a nonexistent file or directory."
    )]
    BadAuthSock,

    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),

    #[cfg(windows)]
    #[error("Pageant: {0}")]
    Pageant(#[from] pageant::Error),
}

/// Load a public key from a file. Ed25519, EC-DSA and RSA keys are supported.
///
/// ```
/// russh::keys::load_public_key("../files/id_ed25519.pub").unwrap();
/// ```
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<ssh_key::PublicKey, Error> {
    let mut pubkey = String::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_string(&mut pubkey)?;

    // First non-blank, non-`#` line: `<algorithm> <base64> [comment]` or a
    // bare base64 blob. The comment may contain spaces.
    let line = pubkey
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or(Error::CouldNotReadKey)?;
    let Some((_, rest)) = line.split_once(char::is_whitespace) else {
        return parse_public_key_base64(line);
    };
    let rest = rest.trim_start();
    let (key, comment) = rest
        .split_once(char::is_whitespace)
        .unwrap_or((rest, ""));
    let mut key = parse_public_key_base64(key)?;
    key.set_comment(comment.trim_start());
    Ok(key)
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// russh::keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key: &str) -> Result<ssh_key::PublicKey, Error> {
    let base = BASE64_MIME.decode(key.as_bytes())?;
    key::parse_public_key(&base)
}

pub trait PublicKeyBase64 {
    /// Create the base64 part of the public key blob.
    fn public_key_bytes(&self) -> Vec<u8>;
    fn public_key_base64(&self) -> String {
        let mut s = BASE64_MIME.encode(&self.public_key_bytes());
        assert_eq!(s.pop(), Some('\n'));
        assert_eq!(s.pop(), Some('\r'));
        s.replace("\r\n", "")
    }
}

impl PublicKeyBase64 for ssh_key::PublicKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.key_data().encoded().unwrap_or_default()
    }
}

impl PublicKeyBase64 for PrivateKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().public_key_bytes()
    }
}

/// Load a secret key, deciphering it with the supplied password if necessary.
pub fn load_secret_key<P: AsRef<Path>>(
    secret_: P,
    password: Option<&str>,
) -> Result<PrivateKey, Error> {
    let mut secret_file = std::fs::File::open(secret_)?;
    let mut secret = String::new();
    secret_file.read_to_string(&mut secret)?;
    decode_secret_key(&secret, password)
}

/// Load a openssh certificate
pub fn load_openssh_certificate<P: AsRef<Path>>(cert_: P) -> Result<Certificate, ssh_key::Error> {
    let mut cert_file = std::fs::File::open(cert_)?;
    let mut cert = String::new();
    cert_file.read_to_string(&mut cert)?;

    Certificate::from_openssh(&cert)
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '/'
        || c == '+'
        || c == '='
}

#[cfg(test)]
mod test {

    #[cfg(unix)]
    use futures::Future;

    use super::*;
    #[cfg(unix)]
    use crate::keys::agent::AgentIdentity;
    use crate::keys::key::PublicKeyExt;

    #[test]
    fn test_load_public_key_comment() {
        const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIK2pr+Bfus1hvPof4Wb/plZCzSbqadHH0u+/f4ODtKnE";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.pub");
        let load = |contents: &str| {
            std::fs::write(&path, contents).unwrap();
            load_public_key(&path).unwrap()
        };

        let key = load(&format!("ssh-ed25519 {KEY} my comment\n"));
        assert_eq!(key.comment().to_string(), "my comment");
        assert_eq!(
            key.to_openssh().unwrap(),
            format!("ssh-ed25519 {KEY} my comment")
        );

        let key = load(&format!("ssh-ed25519 {KEY}\n"));
        assert!(key.comment().is_empty());

        let key = load(&format!("{KEY}\n"));
        assert!(key.comment().is_empty());

        let key = load(&format!("# a comment line\r\n\r\nssh-ed25519\t{KEY}  tabs and crlf \r\n"));
        assert_eq!(key.comment().to_string(), "tabs and crlf");

        for bad in ["", "\n# only a comment\n", "ssh-ed25519 not-base64\n"] {
            std::fs::write(&path, bad).unwrap();
            assert!(load_public_key(&path).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_fingerprint() {
        let key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        )
        .unwrap();
        assert_eq!(
            format!("{}", key.fingerprint(ssh_key::HashAlg::Sha256)),
            "SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn test_parse_p256_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxBTpMIGvo7CnordO7wP0QQRqpBwUjOLl4eMhfucfE1sjTYyK5wmTl1UqoSDS1PtRVTBdl+0+9pquFb46U7fwg=";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP256
                },
        );
    }

    #[test]
    fn test_parse_p384_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBVFgxJxpCaAALZG/S5BHT8/IUQ5mfuKaj7Av9g7Jw59fBEGHfPBz1wFtHGYw5bdLmfVZTIDfogDid5zqJeAKr1AcD06DKTXDzd2EpUjqeLfQ5b3erHuX758fgu/pSDGRA==";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384
                }
        );
    }

    #[test]
    fn test_parse_p521_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAQepXEpOrzlX22r4E5zEHjhHWeZUe//zaevTanOWRBnnaCGWJFGCdjeAbNOuAmLtXc+HZdJTCZGREeSLSrpJa71QDCgZl0N7DkDUanCpHZJe/DCK6qwtHYbEMn28iLMlGCOrCIa060EyJHbp1xcJx4I1SKj/f/fm3DhhID/do6zyf8Cg==";

        assert!(
            parse_public_key_base64(key).unwrap().algorithm()
                == ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP521
                }
        );
    }

    #[test]
    fn test_srhb() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQC0Xtz3tSNgbUQAXem4d+d6hMx7S8Nwm/DOO2AWyWCru+n/+jQ7wz2b5+3oG2+7GbWZNGj8HCc6wJSA3jUsgv1N6PImIWclD14qvoqY3Dea1J0CJgXnnM1xKzBz9C6pDHGvdtySg+yzEO41Xt4u7HFn4Zx5SGuI2NBsF5mtMLZXSi33jCIWVIkrJVd7sZaY8jiqeVZBB/UvkLPWewGVuSXZHT84pNw4+S0Rh6P6zdNutK+JbeuO+5Bav4h9iw4t2sdRkEiWg/AdMoSKmo97Gigq2mKdW12ivnXxz3VfxrCgYJj9WwaUUWSfnAju5SiNly0cTEAN4dJ7yB0mfLKope1kRhPsNaOuUmMUqlu/hBDM/luOCzNjyVJ+0LLB7SV5vOiV7xkVd4KbEGKou8eeCR3yjFazUe/D1pjYPssPL8cJhTSuMc+/UC9zD8yeEZhB9V+vW4NMUR+lh5+XeOzenl65lWYd/nBZXLBbpUMf1AOfbz65xluwCxr2D2lj46iApSIpvE63i3LzFkbGl9GdUiuZJLMFJzOWdhGGc97cB5OVyf8umZLqMHjaImxHEHrnPh1MOVpv87HYJtSBEsN4/omINCMZrk++CRYAIRKRpPKFWV7NQHcvw3m7XLR3KaTYe+0/MINIZwGdou9fLUU3zSd521vDjA/weasH0CyDHq7sZw==";

        parse_public_key_base64(key).unwrap();
    }

    #[test]
    fn test_gpg() {
        env_logger::try_init().unwrap_or(());
        let key = [
            0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 129, 0, 163,
            72, 59, 242, 4, 248, 139, 217, 57, 126, 18, 195, 170, 3, 94, 154, 9, 150, 89, 171, 236,
            192, 178, 185, 149, 73, 210, 121, 95, 126, 225, 209, 199, 208, 89, 130, 175, 229, 163,
            102, 176, 155, 69, 199, 155, 71, 214, 170, 61, 202, 2, 207, 66, 198, 147, 65, 10, 176,
            20, 105, 197, 133, 101, 126, 193, 252, 245, 254, 182, 14, 250, 118, 113, 18, 220, 38,
            220, 75, 247, 50, 163, 39, 2, 61, 62, 28, 79, 199, 238, 189, 33, 194, 190, 22, 87, 91,
            1, 215, 115, 99, 138, 124, 197, 127, 237, 228, 170, 42, 25, 117, 1, 106, 36, 54, 163,
            163, 207, 129, 133, 133, 28, 185, 170, 217, 12, 37, 113, 181, 182, 180, 178, 23, 198,
            233, 31, 214, 226, 114, 146, 74, 205, 177, 82, 232, 238, 165, 44, 5, 250, 150, 236, 45,
            30, 189, 254, 118, 55, 154, 21, 20, 184, 235, 223, 5, 20, 132, 249, 147, 179, 88, 146,
            6, 100, 229, 200, 221, 157, 135, 203, 57, 204, 43, 27, 58, 85, 54, 219, 138, 18, 37,
            80, 106, 182, 95, 124, 140, 90, 29, 48, 193, 112, 19, 53, 84, 201, 153, 52, 249, 15,
            41, 5, 11, 147, 18, 8, 27, 31, 114, 45, 224, 118, 111, 176, 86, 88, 23, 150, 184, 252,
            128, 52, 228, 90, 30, 34, 135, 234, 123, 28, 239, 90, 202, 239, 188, 175, 8, 141, 80,
            59, 194, 80, 43, 205, 34, 137, 45, 140, 244, 181, 182, 229, 247, 94, 216, 115, 173,
            107, 184, 170, 102, 78, 249, 4, 186, 234, 169, 148, 98, 128, 33, 115, 232, 126, 84, 76,
            222, 145, 90, 58, 1, 4, 163, 243, 93, 215, 154, 205, 152, 178, 109, 241, 197, 82, 148,
            222, 78, 44, 193, 248, 212, 157, 118, 217, 75, 211, 23, 229, 121, 28, 180, 208, 173,
            204, 14, 111, 226, 25, 163, 220, 95, 78, 175, 189, 168, 67, 159, 179, 176, 200, 150,
            202, 248, 174, 109, 25, 89, 176, 220, 226, 208, 187, 84, 169, 157, 14, 88, 217, 221,
            117, 254, 51, 45, 93, 184, 80, 225, 158, 29, 76, 38, 69, 72, 71, 76, 50, 191, 210, 95,
            152, 175, 26, 207, 91, 7,
        ];
        ssh_key::PublicKey::decode(&key).unwrap();
    }

    #[cfg(unix)]
    async fn test_client_agent(key: PrivateKey) -> Result<(), Box<dyn std::error::Error>> {
        env_logger::try_init().unwrap_or(());
        use std::process::Stdio;

        let dir = tempfile::tempdir()?;
        let agent_path = dir.path().join("agent");
        let mut agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let public = key.public_key();
        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
        let mut client = agent::client::AgentClient::connect(stream);
        client.add_identity(&key, &[]).await?;
        client.request_identities().await?;
        let buf = b"blabla".to_vec();
        let len = buf.len();
        let buf = client
            .sign_request(
                &AgentIdentity::from(public.clone()),
                Some(HashAlg::Sha256),
                buf,
            )
            .await
            .unwrap();
        let (a, b) = buf.split_at(len);

        match key.public_key().key_data() {
            ssh_key::public::KeyData::Ed25519 { .. } => {
                let sig = &b[b.len() - 64..];
                let sig = ssh_key::Signature::new(key.algorithm(), sig)?;
                use signature::Verifier;
                assert!(Verifier::verify(public, a, &sig).is_ok());
            }
            ssh_key::public::KeyData::Ecdsa { .. } => {}
            _ => {}
        }

        agent.kill().await?;
        agent.wait().await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_client_agent_ed25519() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_client_agent_rsa() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_client_agent_openssh_rsa() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[test]
    #[cfg(all(unix, feature = "rsa"))]
    fn test_agent() {
        env_logger::try_init().unwrap_or(());
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");

        let core = tokio::runtime::Runtime::new().unwrap();
        use agent;
        use signature::Verifier;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {
            fn confirm(
                self,
                _: std::sync::Arc<PrivateKey>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
                Box::new(futures::future::ready((self, true)))
            }
        }
        let agent_path_ = agent_path.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        core.spawn(async move {
            let mut listener = tokio::net::UnixListener::bind(&agent_path_).unwrap();
            let _ = tx.send(());
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        core.block_on(async move {
            let public = key.public_key();
            // make sure the listener created the file handle
            rx.await.unwrap();
            let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
            let mut client = agent::client::AgentClient::connect(stream);
            client
                .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }])
                .await
                .unwrap();
            client.request_identities().await.unwrap();
            let buf = b"blabla".to_vec();
            let len = buf.len();
            let buf = client
                .sign_request(&AgentIdentity::from(public.clone()), None, buf)
                .await
                .unwrap();
            let (a, b) = buf.split_at(len);
            if let ssh_key::public::KeyData::Ed25519 { .. } = public.key_data() {
                let sig = &b[b.len() - 64..];
                let sig = ssh_key::Signature::new(key.algorithm(), sig).unwrap();
                assert!(Verifier::verify(public, a, &sig).is_ok());
            }
        })
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_agent_rejects_duplicate_lifetime() {
        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {}

        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");
        let mut listener = tokio::net::UnixListener::bind(&agent_path).unwrap();
        tokio::spawn(async move {
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = agent::client::AgentClient::connect(stream);
        let lifetime = || agent::Constraint::KeyLifetime { seconds: 60 };
        assert!(client
            .add_identity(&key, &[lifetime(), lifetime()])
            .await
            .is_err());
        assert!(client.request_identities().await.unwrap().is_empty());
        client.add_identity(&key, &[lifetime()]).await.unwrap();
        assert_eq!(client.request_identities().await.unwrap().len(), 1);
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_agent_sign_honors_rsa_hash_flags() {
        use signature::Verifier;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {}

        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");
        let mut listener = tokio::net::UnixListener::bind(&agent_path).unwrap();
        tokio::spawn(async move {
            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });

        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = agent::client::AgentClient::connect(stream);

        let rsa = PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap();
        let ed25519 = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        client.add_identity(&rsa, &[]).await.unwrap();
        client.add_identity(&ed25519, &[]).await.unwrap();

        let data = b"blabla";
        for (hash_alg, expected) in [
            (Some(HashAlg::Sha256), "rsa-sha2-256"),
            (Some(HashAlg::Sha512), "rsa-sha2-512"),
            (None, "ssh-rsa"),
        ] {
            let sig = client
                .sign_request_signature(rsa.public_key(), hash_alg, data)
                .await
                .unwrap();
            assert_eq!(sig.algorithm().as_str(), expected);
            assert!(Verifier::verify(rsa.public_key(), data, &sig).is_ok());
        }

        for hash_alg in [Some(HashAlg::Sha256), Some(HashAlg::Sha512), None] {
            let sig = client
                .sign_request_signature(ed25519.public_key(), hash_alg, data)
                .await
                .unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Ed25519);
            assert!(Verifier::verify(ed25519.public_key(), data, &sig).is_ok());
        }
    }

    #[cfg(unix)]
    struct Incoming<'a> {
        listener: &'a mut tokio::net::UnixListener,
    }

    #[cfg(unix)]
    impl futures::stream::Stream for Incoming<'_> {
        type Item = Result<tokio::net::UnixStream, std::io::Error>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let (sock, _addr) = futures::ready!(self.get_mut().listener.poll_accept(cx))?;
            std::task::Poll::Ready(Some(Ok(sock)))
        }
    }

    /// Helper to spawn an ssh-agent and return the agent process and socket path
    #[cfg(unix)]
    async fn spawn_agent() -> Result<
        (tokio::process::Child, std::path::PathBuf, tempfile::TempDir),
        Box<dyn std::error::Error>,
    > {
        use std::process::Stdio;

        let dir = tempfile::tempdir()?;
        let agent_path = dir.path().join("agent");
        let agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        Ok((agent, agent_path, dir))
    }

    /// Helper to create a test certificate
    #[cfg(unix)]
    fn create_test_cert(ca_key: &PrivateKey, user_key: &PrivateKey) -> ssh_key::Certificate {
        use ssh_key::certificate;
                use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_after = now - 3600; // 1 hour ago
        let valid_before = now + 86400 * 365; // 1 year from now

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();

        builder.serial(1).unwrap();
        builder.key_id("test-cert").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("testuser").unwrap();
        builder.sign(ca_key).unwrap()
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_request_identities_full_with_keys_and_certs() {
        use crate::keys::agent::{AgentIdentity, client::AgentClient};
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create a CA key and user key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let plain_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // Write the keys and certificate to temp files
        let user_key_path = dir.path().join("user_key");
        let cert_path = dir.path().join("user_key-cert.pub");
        let plain_key_path = dir.path().join("plain_key");

        // Write user key (the one to be certified)
        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        // Write certificate
        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Write plain key
        let mut f = std::fs::File::create(&plain_key_path).unwrap();
        f.write_all(
            plain_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &plain_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        // Use ssh-add to add the certificate (it will pick up user_key-cert.pub automatically)
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add for certificate failed");

        // Add plain key
        let status = tokio::process::Command::new("ssh-add")
            .arg(&plain_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add for plain key failed");

        // Connect to agent and test request_identities_full
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        let identities = client.request_identities().await.unwrap();

        // ssh-add with a certificate adds the cert identity, and the plain key adds another
        // The exact count depends on ssh-agent behavior - just verify we have both types
        assert!(!identities.is_empty(), "Expected at least one identity");

        // Count the types
        let mut key_count = 0;
        let mut cert_count = 0;

        for identity in &identities {
            match identity {
                AgentIdentity::PublicKey { .. } => key_count += 1,
                AgentIdentity::Certificate { certificate: c, .. } => {
                    cert_count += 1;
                    // Verify the certificate matches what we created
                    assert_eq!(c.key_id(), "test-cert");
                    // Verify public_key() works
                    let pk = identity.public_key();
                    assert_eq!(pk.key_data(), c.public_key());
                }
            }
            // Verify comment() works
            let _ = identity.comment();
        }

        // We should have at least one of each (ssh-add may add both key and cert for the same identity)
        assert!(
            key_count >= 1,
            "Expected at least 1 public key, got {}",
            key_count
        );
        assert!(
            cert_count >= 1,
            "Expected at least 1 certificate, got {}",
            cert_count
        );

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_sign_request_cert() {
        use crate::keys::agent::client::AgentClient;
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create a CA key and user key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // Write the key and certificate to temp files
        let user_key_path = dir.path().join("user_key");
        let cert_path = dir.path().join("user_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Use ssh-add to add the certificate
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // Connect to agent and test sign_request_cert
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Create data to sign
        let data_to_sign = b"test data to sign";
        let buf = data_to_sign.to_vec();
        let len = buf.len();

        // Sign using the certificate (None for hash_alg since Ed25519 doesn't need it)
        let signed_buf = client.sign_request(&cert.into(), None, buf).await.unwrap();

        // Verify the signature is appended to the original data
        assert!(signed_buf.len() > len, "Signed buffer should be larger");

        // Extract and verify signature
        let (original, sig_data) = signed_buf.split_at(len);
        assert_eq!(original, data_to_sign);

        // The signature should be valid
        // For ed25519, signature is 64 bytes, but encoded with type prefix
        assert!(sig_data.len() > 64, "Signature data should include type");

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_sign_request_cert_missing_key_returns_agent_failure() {
        use crate::keys::agent::client::AgentClient;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, _dir) = spawn_agent().await.unwrap();

        // Create a CA key and user key, but DON'T add them to the agent
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // Connect to agent WITHOUT adding any keys
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Verify the agent has no keys
        let identities = client.request_identities().await.unwrap();
        assert!(identities.is_empty(), "Agent should have no keys");

        // Create data to sign
        let data_to_sign = b"test data to sign";
        let buf = data_to_sign.to_vec();

        // Try to sign using the certificate - should fail because the key isn't in the agent
        let result = client.sign_request(&cert.into(), None, buf).await;

        // Verify we get an AgentFailure error
        assert!(
            result.is_err(),
            "Signing should fail when key is not in agent"
        );
        match result {
            Err(Error::AgentFailure) => {
                // This is the expected error
            }
            Err(e) => {
                panic!("Expected AgentFailure error, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected error, but signing succeeded");
            }
        }

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_sign_request_missing_key_returns_agent_failure() {
        use crate::keys::agent::client::AgentClient;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, _dir) = spawn_agent().await.unwrap();

        // Create a key but DON'T add it to the agent
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Connect to agent WITHOUT adding any keys
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Verify the agent has no keys
        let identities = client.request_identities().await.unwrap();
        assert!(identities.is_empty(), "Agent should have no keys");

        // Create data to sign
        let data_to_sign = b"test data to sign";
        let buf = data_to_sign.to_vec();

        // Try to sign using the public key - should fail because the key isn't in the agent
        let result = client
            .sign_request(&key.public_key().clone().into(), None, buf)
            .await;

        // Verify we get an AgentFailure error
        assert!(
            result.is_err(),
            "Signing should fail when key is not in agent"
        );
        match result {
            Err(Error::AgentFailure) => {
                // This is the expected error
            }
            Err(e) => {
                panic!("Expected AgentFailure error, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected error, but signing succeeded");
            }
        }

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    /// Helper to create a test RSA certificate
    #[cfg(all(unix, feature = "rsa"))]
    fn create_test_rsa_cert(ca_key: &PrivateKey, user_key: &PrivateKey) -> ssh_key::Certificate {
        use ssh_key::certificate;
                use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_after = now - 3600; // 1 hour ago
        let valid_before = now + 86400 * 365; // 1 year from now

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();

        builder.serial(1).unwrap();
        builder.key_id("test-rsa-cert").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("testuser").unwrap();
        builder.sign(ca_key).unwrap()
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_sign_request_cert_rsa() {
        use crate::keys::agent::client::AgentClient;
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create RSA CA key and user key
        let ca_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
        )
        .unwrap();
        let user_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
        )
        .unwrap();

        // Create a certificate
        let cert = create_test_rsa_cert(&ca_key, &user_key);

        // Write the key and certificate to temp files
        let user_key_path = dir.path().join("user_rsa_key");
        let cert_path = dir.path().join("user_rsa_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Use ssh-add to add the certificate
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // Connect to agent and test sign_request_cert
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Create data to sign
        let data_to_sign = b"test data to sign with RSA cert";
        let buf = data_to_sign.to_vec();
        let len = buf.len();

        // Sign using the certificate with SHA-256 hash algorithm
        let signed_buf = client
            .sign_request(&cert.into(), Some(HashAlg::Sha256), buf)
            .await
            .unwrap();

        // Verify the signature is appended to the original data
        assert!(signed_buf.len() > len, "Signed buffer should be larger");

        // Extract and verify signature
        let (original, sig_data) = signed_buf.split_at(len);
        assert_eq!(original, data_to_sign);

        // The RSA signature should be substantial
        assert!(
            sig_data.len() > 100,
            "RSA signature data should be substantial"
        );

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }

    #[tokio::test]
    #[cfg(all(unix, feature = "rsa"))]
    async fn test_sign_request_cert_rsa_sha512() {
        use crate::keys::agent::client::AgentClient;
                use std::io::Write;
        use std::process::Stdio;

        env_logger::try_init().unwrap_or(());

        let (mut agent, agent_path, dir) = spawn_agent().await.unwrap();

        // Create RSA CA key and user key
        let ca_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .unwrap();
        let user_key = PrivateKey::random(
            &mut rand::rng(),
            ssh_key::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .unwrap();

        // Create a certificate
        let cert = create_test_rsa_cert(&ca_key, &user_key);

        // Write the key and certificate to temp files
        let user_key_path = dir.path().join("user_rsa_key");
        let cert_path = dir.path().join("user_rsa_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        // Use ssh-add to add the certificate
        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // Connect to agent and test sign_request_cert with SHA-512
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut client = AgentClient::connect(stream);

        // Create data to sign
        let data_to_sign = b"test data to sign with RSA cert SHA-512";
        let buf = data_to_sign.to_vec();
        let len = buf.len();

        // Sign using the certificate with SHA-512 hash algorithm
        let signed_buf = client
            .sign_request(&cert.into(), Some(HashAlg::Sha512), buf)
            .await
            .unwrap();

        // Verify the signature is appended to the original data
        assert!(signed_buf.len() > len, "Signed buffer should be larger");

        // Extract and verify signature
        let (original, sig_data) = signed_buf.split_at(len);
        assert_eq!(original, data_to_sign);

        // The RSA signature should be substantial
        assert!(
            sig_data.len() > 100,
            "RSA signature data should be substantial"
        );

        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }
}
