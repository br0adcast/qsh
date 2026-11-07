//! Read-only discovery through an already trusted SSH endpoint.
use std::sync::Arc;

use serde::Deserialize;

use crate::{SshAuthPlan, SshError, SshEvents, SshParams};
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

/// Never installs, authorizes a client, prompts for trust, or alters the daemon.
pub fn discover_server_info(
    params: SshParams,
    auth: SshAuthPlan,
    bind: Arc<dyn knock::SocketBind>,
    expected_qsh_key: [u8; 32],
    cancel: &knock::Cancel,
) -> Result<Option<VerifiedSshServerInfo>, SshError> {
    if params.known_host_keys.is_empty() {
        return Err(SshError::Protocol(
            "server discovery requires a verified SSH host key".into(),
        ));
    }
    struct Silent;
    impl SshEvents for Silent {
        fn on_channel(&self, _: client::channel::SubstrateEvent) {}
        fn on_closed(&self, _: String) {}
    }
    // The transport RNG already obtains fresh entropy for every private key.
    let challenge = transport::generate_keypair().public;
    crate::runtime().block_on(async {
        let (handle, _) = crate::establish(
            &params,
            auth,
            bind,
            &Silent,
            Arc::new(crate::write_budget::WriteCredits::default()),
            cancel,
        )
        .await?;
        let exchange = async {
            let mut channel = handle
                .channel_open_session()
                .await
                .map_err(|e| SshError::Protocol(e.to_string()))?;
            channel
                .exec(
                    true,
                    format!("qshd server-info --challenge {}", hex(&challenge)),
                )
                .await
                .map_err(|e| SshError::Protocol(e.to_string()))?;
            let mut output = Vec::new();
            let mut success = false;
            while let Some(message) = channel.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => {
                        if output.len() + data.len() > 4096 {
                            return Ok(None);
                        }
                        output.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => success = exit_status == 0,
                    russh::ChannelMsg::Close => break,
                    _ => (),
                }
            }
            Ok(if success {
                parse_response(&output, &challenge, &expected_qsh_key)
                    .map(|info| VerifiedSshServerInfo { info })
            } else {
                None
            })
        };
        crate::with_cancel(
            tokio::time::timeout(params.connect_timeout, exchange),
            cancel,
        )
        .await?
        .unwrap_or(Ok(None))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fake_server::{FakeAuth, FakeServer, ServerActivity};

    fn params(server: &FakeServer) -> SshParams {
        SshParams {
            host: "127.0.0.1".into(),
            port: server.port,
            username: "fixture".into(),
            known_host_keys: vec![server.host_public_key_wire()],
            connect_timeout: std::time::Duration::from_secs(2),
            keepalive_interval: std::time::Duration::ZERO,
            compression: false,
            tcp_nodelay: true,
            knock: Vec::new(),
        }
    }
    fn auth() -> SshAuthPlan {
        SshAuthPlan::single(crate::AuthMethod::Password(crate::Zeroizing::new(
            "fixture-password".into(),
        )))
    }
    #[test]
    fn verified_ssh_discovery_is_read_only_fresh_and_identity_bound() {
        let activity = Arc::new(ServerActivity::default());
        let server = FakeServer::start(FakeAuth {
            password: Some("fixture-password".into()),
            activity: activity.clone(),
            exec_reply: Some(Arc::new(|command| {
                let command = std::str::from_utf8(command).unwrap();
                let challenge = command
                    .strip_prefix("qshd server-info --challenge ")
                    .unwrap();
                assert_eq!(challenge.len(), 64);
                serde_json::to_vec(&serde_json::json!({"challenge":challenge,
                    "server_pubkey":hex(&[2;32]), "generation":hex(&[3;16]),
                    "core_version":"1.2.3", "session_protocols":[[2,2,2]]}))
                .unwrap()
            })),
            ..Default::default()
        });
        let cancel = knock::Cancel::new();
        for _ in 0..2 {
            let proof = discover_server_info(
                params(&server),
                auth(),
                Arc::new(knock::NoBind),
                [2; 32],
                &cancel,
            )
            .unwrap()
            .unwrap();
            assert_eq!(proof.info().generation, [3; 16]);
        }
        assert!(discover_server_info(
            params(&server),
            auth(),
            Arc::new(knock::NoBind),
            [9; 32],
            &cancel
        )
        .unwrap()
        .is_none());
        let commands = activity.commands.lock().unwrap();
        assert_eq!(commands.len(), 3);
        assert_ne!(
            commands[0], commands[1],
            "each query needs a fresh challenge"
        );
        assert_eq!(
            server
                .sftp_channels
                .opened
                .load(std::sync::atomic::Ordering::SeqCst),
            3
        );
        assert_eq!(
            server
                .sftp_channels
                .writes
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn ssh_discovery_rejects_unknown_changed_hosts_and_legacy_or_oversized_output() {
        let activity = Arc::new(ServerActivity::default());
        let server = FakeServer::start(FakeAuth {
            password: Some("fixture-password".into()),
            activity: activity.clone(),
            exec_outputs: vec![b"legacy unsupported command".to_vec(), vec![b'x'; 4097]],
            ..Default::default()
        });
        let cancel = knock::Cancel::new();
        let mut unknown = params(&server);
        unknown.known_host_keys.clear();
        assert!(
            discover_server_info(unknown, auth(), Arc::new(knock::NoBind), [2; 32], &cancel)
                .is_err()
        );
        assert_eq!(
            activity
                .connections
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            activity.userauth.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let mut changed = params(&server);
        let other = FakeServer::start(FakeAuth::default());
        changed.known_host_keys = vec![other.host_public_key_wire()];
        assert!(
            discover_server_info(changed, auth(), Arc::new(knock::NoBind), [2; 32], &cancel)
                .is_err()
        );
        assert_eq!(activity.exec.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            activity.userauth.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        for _ in 0..2 {
            assert!(discover_server_info(
                params(&server),
                auth(),
                Arc::new(knock::NoBind),
                [2; 32],
                &cancel
            )
            .unwrap()
            .is_none());
        }
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
