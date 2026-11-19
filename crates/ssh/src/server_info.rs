//! Read-only `server-info` evidence from an already verified SSH login.
//! The exchange runs inside the bring-up's own session (`bringup`), never
//! on a login of its own.
use serde::Deserialize;

use transport::bootstrap::{ServerInfo, SessionProfile};

/// Evidence constructed only after verified SSH authentication and identity binding.
#[derive(Clone, Debug)]
pub struct VerifiedSshServerInfo {
    info: ServerInfo,
}

impl VerifiedSshServerInfo {
    pub fn info(&self) -> &ServerInfo {
        &self.info
    }
}

#[derive(Deserialize)]
struct Response {
    challenge: String,
    server_pubkey: String,
    generation: String,
    core_version: String,
    session_protocols: Vec<[u8; 3]>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh challenge for one query.
pub fn challenge() -> [u8; 32] {
    // The transport RNG already obtains fresh entropy for every private key.
    transport::generate_keypair().public
}

/// The arguments after the trusted `qshd` path.
pub fn arguments(challenge: &[u8; 32]) -> String {
    format!("server-info --challenge {}", hex(challenge))
}

/// The reply of a successful query, bound to its challenge and the pinned key.
pub fn verify(
    reply: &[u8],
    challenge: &[u8; 32],
    expected_qsh_key: &[u8; 32],
) -> Option<VerifiedSshServerInfo> {
    parse_response(reply, challenge, expected_qsh_key).map(|info| VerifiedSshServerInfo { info })
}

fn parse_response(bytes: &[u8], challenge: &[u8; 32], key: &[u8; 32]) -> Option<ServerInfo> {
    if bytes.len() > 4096 {
        return None;
    }
    let reply: Response = serde_json::from_slice(bytes).ok()?;
    if reply.challenge != hex(challenge)
        || reply.server_pubkey != hex(key)
        || reply.core_version.len() > 128
        || reply.session_protocols.len() > 16
        || reply.generation.len() != 32
    {
        return None;
    }
    let mut generation = [0; 16];
    for (slot, pair) in generation
        .iter_mut()
        .zip(reply.generation.as_bytes().as_chunks::<2>().0.iter())
    {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    let info = ServerInfo {
        generation,
        core_version: reply.core_version,
        session_protocols: reply
            .session_protocols
            .into_iter()
            .map(|p| SessionProfile {
                wire: p[0],
                handshake: p[1],
                channel: p[2],
            })
            .collect(),
    };
    transport::bootstrap::encode_server_info(&info).ok()?;
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_query_has_a_fresh_challenge_and_exact_arguments() {
        let (a, b) = (challenge(), challenge());
        assert_ne!(a, b, "each query needs a fresh challenge");
        assert_eq!(
            arguments(&[0xab; 32]),
            format!("server-info --challenge {}", "ab".repeat(32))
        );
    }

    #[test]
    fn verify_binds_the_reply_to_its_challenge_and_pinned_key() {
        let reply = serde_json::to_vec(&serde_json::json!({"challenge":hex(&[1;32]),
            "server_pubkey":hex(&[2;32]), "generation":hex(&[3;16]),
            "core_version":"1.2.3", "session_protocols":[[2,2,2]]}))
        .unwrap();
        assert_eq!(
            verify(&reply, &[1; 32], &[2; 32])
                .unwrap()
                .info()
                .generation,
            [3; 16]
        );
        assert!(verify(&reply, &[9; 32], &[2; 32]).is_none());
        assert!(verify(&reply, &[1; 32], &[9; 32]).is_none());
        assert!(verify(b"legacy unsupported command", &[1; 32], &[2; 32]).is_none());
    }

    #[test]
    fn response_requires_challenge_identity_and_bounded_metadata() {
        let mut value = serde_json::json!({"challenge":hex(&[1;32]),"server_pubkey":hex(&[2;32]),
            "generation":hex(&[3;16]),"core_version":"1.2.3", "session_protocols":[[2,2,2]]});
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            parse_response(&bytes, &[1; 32], &[2; 32])
                .unwrap()
                .generation,
            [3; 16]
        );
        assert!(parse_response(&bytes, &[9; 32], &[2; 32]).is_none());
        assert!(parse_response(&bytes, &[1; 32], &[9; 32]).is_none());
        value["core_version"] = "x".repeat(129).into();
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), &[1; 32], &[2; 32]).is_none());
        assert!(parse_response(&vec![b' '; 4097], &[1; 32], &[2; 32]).is_none());
        for malformed in ["", "\x1b]52;fixture\x07", "☃"] {
            value["core_version"] = malformed.into();
            assert!(
                parse_response(&serde_json::to_vec(&value).unwrap(), &[1; 32], &[2; 32]).is_none()
            );
        }
        value["core_version"] = "unknown".into();
        assert!(parse_response(&serde_json::to_vec(&value).unwrap(), &[1; 32], &[2; 32]).is_some());
    }
}
