//! The server's host key: how it is shown to a person and how it is
//! compared with the one remembered for the address.

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::HostKeyInfo;

/// Type, wire bytes and `SHA256:` fingerprint of a host key given in SSH
/// wire format. The fingerprint is unpadded base64 -- the form ssh-keygen
/// prints and the daemon's own fingerprint uses.
pub fn host_key_info(key_wire: &[u8]) -> Result<HostKeyInfo, String> {
    let key_type = read_string(key_wire).ok_or_else(|| "a host key without a type".to_string())?;
    let digest = Sha256::digest(key_wire);
    Ok(HostKeyInfo {
        key_type: String::from_utf8_lossy(key_type).into_owned(),
        key: key_wire.to_vec(),
        fingerprint: format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        ),
    })
}

fn read_string(buf: &[u8]) -> Option<&[u8]> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    buf.get(4..4usize.checked_add(len)?)
}

/// What the offered key means for this address.
pub(crate) enum Verdict {
    Trusted,
    Unknown,
    Changed,
}

pub(crate) fn judge(offered: &[u8], known: &[Vec<u8>]) -> Verdict {
    if known.is_empty() {
        Verdict::Unknown
    } else if known.iter().any(|k| k == offered) {
        Verdict::Trusted
    } else {
        Verdict::Changed
    }
}

/// Host-key algorithms to offer: those of the known keys first (in list
/// order), then the remaining defaults. For a known RSA key, SHA-2 host
/// signatures come first; the default `ssh-rsa` (SHA-1) signature remains
/// last. An unrecognised known key, or one of a type russh does not offer
/// by default (`ssh-dss`, security keys), is skipped.
pub(crate) fn host_key_preference(known: &[Vec<u8>]) -> Vec<russh::keys::Algorithm> {
    use russh::keys::{Algorithm, HashAlg, PublicKey};
    let defaults = russh::Preferred::default().key;
    let push = |a: Algorithm, out: &mut Vec<Algorithm>| {
        if defaults.contains(&a) && !out.contains(&a) {
            out.push(a);
        }
    };
    let mut out: Vec<Algorithm> = Vec::new();
    for wire in known {
        let Ok(key) = PublicKey::from_bytes(wire) else {
            continue;
        };
        match key.algorithm() {
            Algorithm::Rsa { .. } => {
                push(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    &mut out,
                );
                push(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    &mut out,
                );
            }
            other => push(other, &mut out),
        }
    }
    for a in defaults.iter() {
        push(a.clone(), &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire bytes of a fresh ecdsa-sha2-nistp256 public key.
    fn ecdsa_wire() -> Vec<u8> {
        let key = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        );
        let point = key.verifying_key().to_sec1_point(false);
        let mut out = Vec::new();
        for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", point.as_bytes()] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn known_types_come_first_without_duplicates() {
        let order = host_key_preference(&[ecdsa_wire()]);
        assert_eq!(order[0].as_str(), "ecdsa-sha2-nistp256");
        let mut seen = std::collections::HashSet::new();
        assert!(order.iter().all(|a| seen.insert(a.as_str().to_string())));
        // The defaults keep SHA-1 `ssh-rsa` last; nothing here moves it up.
        assert_eq!(order.last().map(|a| a.as_str()), Some("ssh-rsa"));
    }

    #[test]
    fn several_known_keys_keep_their_list_order() {
        let mut ed = Vec::new();
        for part in [&b"ssh-ed25519"[..], &[7u8; 32][..]] {
            ed.extend_from_slice(&(part.len() as u32).to_be_bytes());
            ed.extend_from_slice(part);
        }
        let order = host_key_preference(&[ecdsa_wire(), ed]);
        assert_eq!(order[0].as_str(), "ecdsa-sha2-nistp256");
        assert_eq!(order[1].as_str(), "ssh-ed25519");
    }

    #[test]
    fn an_unrecognised_known_key_is_skipped() {
        let defaults = host_key_preference(&[]);
        assert_eq!(host_key_preference(&[vec![1, 2, 3]]), defaults);
    }

    /// A known key whose type russh would not negotiate (a security key's
    /// `sk-ssh-ed25519@openssh.com`) is not offered: the defaults stay as
    /// they are.
    #[test]
    fn a_known_key_of_a_type_russh_does_not_offer_is_left_out() {
        let mut sk = Vec::new();
        for part in [&b"sk-ssh-ed25519@openssh.com"[..], &[7u8; 32][..], b"ssh:"] {
            sk.extend_from_slice(&(part.len() as u32).to_be_bytes());
            sk.extend_from_slice(part);
        }
        assert!(russh::keys::PublicKey::from_bytes(&sk).is_ok());
        assert_eq!(host_key_preference(&[sk]), host_key_preference(&[]));
    }

    #[test]
    fn judge_follows_the_known_list() {
        assert!(matches!(judge(b"a", &[]), Verdict::Unknown));
        assert!(matches!(
            judge(b"a", &[b"b".to_vec(), b"a".to_vec()]),
            Verdict::Trusted
        ));
        assert!(matches!(judge(b"a", &[b"b".to_vec()]), Verdict::Changed));
    }
}
