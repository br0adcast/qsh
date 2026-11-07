//! Read-only actual-running-daemon discovery for verified SSH callers.
use anyhow::{bail, Context, Result};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use transport::bootstrap::{ServerInfo, SessionProfile};

static PROCESS_GENERATION: Mutex<Option<(u32, [u8; 16])>> = Mutex::new(None);

pub fn current() -> ServerInfo {
    let pid = std::process::id();
    let mut generation = PROCESS_GENERATION.lock().expect("process generation mutex");
    if generation.as_ref().is_none_or(|(owner, _)| *owner != pid) {
        let mut value = [0; 16];
        rand_core::OsRng.fill_bytes(&mut value);
        *generation = Some((pid, value));
    }
    ServerInfo {
        generation: generation.as_ref().expect("initialized generation").1,
        core_version: crate::state::QSHD_VERSION.to_owned(),
        session_protocols: vec![SessionProfile {
            wire: transport::wire::VERSION,
            handshake: transport::handshake_payload::HS_VERSION,
            channel: transport::channel::PROTOCOL_VERSION,
        }],
    }
}
#[derive(Clone, Debug)]
pub struct RunningServerInfo {
    pub public_key: [u8; 32],
    pub info: ServerInfo,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub challenge: String,
    pub server_pubkey: String,
    pub generation: String,
    pub core_version: String,
    pub session_protocols: Vec<[u8; 3]>,
}
impl RunningServerInfo {
    pub fn response(&self, challenge: [u8; 32]) -> Result<String> {
        transport::bootstrap::encode_server_info(&self.info)?;
        let response = Response {
            challenge: hex::encode(challenge),
            server_pubkey: hex::encode(self.public_key),
            generation: hex::encode(self.info.generation),
            core_version: self.info.core_version.clone(),
            session_protocols: self
                .info
                .session_protocols
                .iter()
                .map(|p| [p.wire, p.handshake, p.channel])
                .collect(),
        };
        let mut line = serde_json::to_string(&response)?;
        line.push('\n');
        Ok(line)
    }
}

/// Queries local daemon control only; never loads identity keys or starts a daemon.
pub fn run_command(args: &[std::ffi::OsString]) -> Result<()> {
    let mut challenge = None;
    let mut socket = None;
    let mut i = 1;
    while i < args.len() {
        let option = args[i].to_str().context("invalid server-info argument")?;
        i += 1;
        let value = args.get(i).context("missing server-info option value")?;
        match option {
            "--challenge" if challenge.is_none() => {
                let raw = hex::decode(value.to_str().context("invalid challenge")?)?;
                challenge = Some(
                    <[u8; 32]>::try_from(raw)
                        .map_err(|_| anyhow::anyhow!("challenge must contain 32 bytes"))?,
                );
            }
            "--socket" if socket.is_none() => socket = Some(std::path::PathBuf::from(value)),
            _ => bail!("unsupported server-info option"),
        }
        i += 1;
    }
    let challenge = challenge.context("server-info requires --challenge")?;
    let socket = match socket {
        Some(path) => path,
        None => crate::serve::cache_dir(false)?.join("control.sock"),
    };
    match crate::control::client_request(
        &socket,
        &crate::control::ControlRequest::ServerInfo(challenge),
    )? {
        crate::control::ControlReply::Answered(line) => {
            if line.len() > 4096 {
                bail!("server-info response exceeds limit");
            }
            let response: Response =
                serde_json::from_str(&line).context("invalid daemon server-info response")?;
            if response.challenge != hex::encode(challenge) {
                bail!("server-info challenge mismatch");
            }
            println!("{line}");
            Ok(())
        }
        _ => bail!("running daemon server information unavailable"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_info_generation_is_shared_and_control_echoes_live_values() {
        let info = current();
        assert_eq!(info, current());
        let running = RunningServerInfo {
            public_key: [3; 32],
            info: ServerInfo {
                core_version: "0.5.9".into(),
                ..info
            },
        };
        let response: Response = serde_json::from_str(&running.response([8; 32]).unwrap()).unwrap();
        assert_eq!(response.core_version, "0.5.9");
        assert_eq!(response.challenge, hex::encode([8; 32]));
        assert_eq!(response.server_pubkey, hex::encode([3; 32]));
    }
}
