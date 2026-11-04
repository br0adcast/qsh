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

/// RSA with SHA-1: the `ssh-rsa` signature algorithm, refused on SSH as on QSH.
pub(crate) const LEGACY_RSA: russh::keys::Algorithm = russh::keys::Algorithm::Rsa { hash: None };

/// Host-key algorithms to offer: those of the known keys first (in list
/// order), then the remaining defaults. An RSA host key is used only through
/// SHA-2 signatures (`rsa-sha2-512`, `rsa-sha2-256`): legacy `ssh-rsa`
/// (SHA-1) is never offered, so a server with nothing better fails the
/// handshake (see `negotiation_error`). An unrecognised known key, or one of
/// a type russh does not offer by default (`ssh-dss`, security keys), is
/// skipped.
pub(crate) fn host_key_preference(known: &[Vec<u8>]) -> Vec<russh::keys::Algorithm> {
    use russh::keys::{Algorithm, HashAlg, PublicKey};
    let defaults = russh::Preferred::default().key;
    let push = |a: Algorithm, out: &mut Vec<Algorithm>| {
        if a != LEGACY_RSA && defaults.contains(&a) && !out.contains(&a) {
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

/// A failed algorithm negotiation as the person reads it, naming what the
/// server offered. SHA-1 is named as the reason only when the server's
/// host-key offer itself contains `ssh-rsa`: the offer is the only evidence
/// of what the server can do, and says nothing of what else it would accept.
/// The names come from the unauthenticated peer and may hold ASCII control
/// characters, so they are shown escaped. `None` for any other error.
pub(crate) fn negotiation_error(error: &russh::Error) -> Option<String> {
    let russh::Error::NoCommonAlgo { kind, theirs, .. } = error else {
        return None;
    };
    let offered = theirs
        .iter()
        .map(|name| name.escape_debug().to_string())
        .collect::<Vec<_>>()
        .join(",");
    Some(match kind {
        russh::AlgorithmKind::Key if theirs.iter().any(|a| a == LEGACY_RSA.as_str()) => format!(
            "no common host-key algorithm (offered: {offered}): legacy ssh-rsa (SHA-1) host \
             signatures are not accepted; an Ed25519, ECDSA or rsa-sha2 host key on the \
             server would be"
        ),
        russh::AlgorithmKind::Key => format!("no common host-key algorithm (offered: {offered})"),
        russh::AlgorithmKind::Kex => {
            format!("no common key-exchange algorithm (offered: {offered})")
        }
        russh::AlgorithmKind::Cipher => format!("no common cipher (offered: {offered})"),
        russh::AlgorithmKind::Mac => format!("no common MAC algorithm (offered: {offered})"),
        russh::AlgorithmKind::Compression => {
            format!("no common compression method (offered: {offered})")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_common(kind: russh::AlgorithmKind, theirs: &[&str]) -> russh::Error {
        russh::Error::NoCommonAlgo {
            kind,
            ours: vec!["ssh-ed25519".into()],
            theirs: theirs.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// Only a host-key offer that contains `ssh-rsa` is explained by SHA-1;
    /// other failed negotiations stay generic, naming the server's offer.
    #[test]
    fn a_failed_negotiation_names_sha1_only_when_the_offer_shows_it() {
        let legacy =
            negotiation_error(&no_common(russh::AlgorithmKind::Key, &["ssh-rsa"])).unwrap();
        assert!(legacy.contains("(offered: ssh-rsa)") && legacy.contains("legacy ssh-rsa (SHA-1)"));
        for (kind, theirs) in [
            (russh::AlgorithmKind::Key, &["ssh-dss"][..]),
            (russh::AlgorithmKind::Kex, &["ssh-rsa"][..]),
            (russh::AlgorithmKind::Cipher, &["3des-cbc"][..]),
        ] {
            let generic = negotiation_error(&no_common(kind, theirs)).unwrap();
            assert!(!generic.contains("SHA-1"), "{generic}");
            assert!(
                generic.contains(&format!("(offered: {})", theirs[0])),
                "{generic}"
            );
        }
        assert_eq!(negotiation_error(&russh::Error::Disconnect), None);
    }

    /// The peer's names are shown escaped: no raw control byte reaches the
    /// message, and ordinary names stay as they are.
    #[test]
    fn a_failed_negotiation_shows_the_offer_without_control_bytes() {
        for kind in [russh::AlgorithmKind::Key, russh::AlgorithmKind::Cipher] {
            let message = negotiation_error(&no_common(
                kind,
                &[
                    "ssh-rsa",
                    "x\u{1b}]0;title\u{7}\r\nforged: line\u{7f}",
                    "rsa-sha2-512",
                ],
            ))
            .unwrap();
            assert!(
                !message.chars().any(|c| c.is_ascii_control()),
                "{message:?}"
            );
            assert!(
                message.contains(
                    "ssh-rsa,x\\u{1b}]0;title\\u{7}\\r\\nforged: line\\u{7f},rsa-sha2-512"
                ),
                "{message}"
            );
        }
    }

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
        assert!(!order.contains(&LEGACY_RSA), "{order:?}");
    }

    /// A known RSA host key is offered through SHA-2 only, with SHA-512 first.
    #[test]
    fn a_known_rsa_key_never_offers_sha1() {
        let pair = ssh_key::private::RsaKeypair::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            2048,
        )
        .unwrap();
        let rsa = ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Rsa(pair), "").unwrap();
        let wire = rsa.public_key().to_bytes().unwrap();
        let order = host_key_preference(&[wire]);
        let names: Vec<&str> = order.iter().map(|a| a.as_str()).collect();
        assert_eq!(names[..2], ["rsa-sha2-512", "rsa-sha2-256"]);
        assert!(!names.contains(&"ssh-rsa"), "{names:?}");
        assert!(!host_key_preference(&[]).contains(&LEGACY_RSA));
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
