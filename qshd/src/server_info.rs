//! Read-only actual-running-daemon discovery for verified SSH callers.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use transport::bootstrap::{ServerInfo, SessionProfile};

static PROCESS_GENERATION: Mutex<Option<(u32, [u8; 16])>> = Mutex::new(None);

pub fn current() -> ServerInfo {
    let pid = std::process::id();
    let mut generation = PROCESS_GENERATION.lock().expect("process generation mutex");
    if generation.as_ref().is_none_or(|(owner, _)| *owner != pid) {
        let mut value = [0; 16];
        getrandom::fill(&mut value).expect("operating system randomness is available");
        *generation = Some((pid, value));
    }
    ServerInfo {
        generation: generation.as_ref().expect("initialized generation").1,
        core_version: crate::state::QSHD_VERSION.to_owned(),
        session_protocols: own_profiles(),
    }
}

/// The session profiles this binary serves.
fn own_profiles() -> Vec<SessionProfile> {
    vec![SessionProfile {
        wire: transport::wire::VERSION,
        handshake: transport::handshake_payload::HS_VERSION,
        channel: transport::channel::PROTOCOL_VERSION,
    }]
}

/// What a client meets when it reaches the daemon: the frontend that serves
/// its sessions. On a hosted daemon (#529) that is a frontend process, which
/// a newer image can replace while the host keeps its pid and its own binary,
/// so this is not necessarily the host's binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontendIdentity {
    pub version: String,
    pub build: u64,
    /// sha256 of the frontend's image, lower-case hex: the form `STATUS` and
    /// `reconcile` use.
    pub checksum: String,
    pub profiles: Vec<SessionProfile>,
    pub generation: [u8; 16],
}

impl FrontendIdentity {
    /// This identity as the daemon names itself to a busy-daemon decision
    /// and to a conditional registration: the pid stays the host's.
    pub fn busy_identity(&self) -> daemon_bootstrap_protocol::BusyDaemonIdentity {
        daemon_bootstrap_protocol::BusyDaemonIdentity {
            version: self.version.clone(),
            build: self.build,
            checksum: self.checksum.clone(),
            pid: std::process::id(),
            generation: Some(hex::encode(self.generation)),
        }
    }
}

/// The one description of the serving frontend that every identity surface
/// reads (`STATUS`, `SERVER-INFO`, `REGISTRATION-INFO`, `ADD-CLIENT-IF`), so
/// that after a frontend replacement none of them still describes the
/// host's own binary. One per daemon.
#[derive(Debug)]
pub struct Serving {
    hosted: bool,
    /// The generation this binary serves under until another frontend is set.
    own_generation: [u8; 16],
    /// The frontend a replacement made serve; `None` while this binary does.
    replaced: Mutex<Option<FrontendIdentity>>,
}

impl Serving {
    /// This binary serving, under this process's generation. `hosted`: the
    /// daemon is a host whose frontends a replacement may change. The
    /// checksum is not computed here but on the first [`Serving::identity`]:
    /// hashing the image can take seconds under load (see
    /// [`crate::state::self_checksum`]).
    pub fn own(hosted: bool) -> Arc<Serving> {
        Arc::new(Serving {
            hosted,
            own_generation: current().generation,
            replaced: Mutex::new(None),
        })
    }

    /// The frontend that serves now. Fails only while this binary serves and
    /// its own checksum cannot be computed.
    pub fn identity(&self) -> Result<FrontendIdentity> {
        if let Some(identity) = self.replaced() {
            return Ok(identity);
        }
        Ok(FrontendIdentity {
            version: crate::state::QSHD_VERSION.to_owned(),
            build: crate::state::build_label(),
            checksum: crate::state::self_checksum()?,
            profiles: own_profiles(),
            generation: self.own_generation,
        })
    }

    /// The serving frontend's generation, without hashing anything.
    pub fn generation(&self) -> [u8; 16] {
        self.replaced()
            .map_or(self.own_generation, |identity| identity.generation)
    }

    /// The serving frontend's in-band server information, without hashing
    /// anything: it names no checksum.
    fn server_info(&self) -> ServerInfo {
        match self.replaced() {
            Some(identity) => ServerInfo {
                generation: identity.generation,
                core_version: identity.version,
                session_protocols: identity.profiles,
            },
            None => ServerInfo {
                generation: self.own_generation,
                core_version: crate::state::QSHD_VERSION.to_owned(),
                session_protocols: own_profiles(),
            },
        }
    }

    /// `identity` serves from now on: a replacement's new frontend is ready.
    pub fn set(&self, identity: FrontendIdentity) {
        *self.replaced.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);
    }

    /// The host behind a hosted daemon: this binary, whichever frontend
    /// serves. `None` for a daemon that is no host, as from an older one.
    pub fn host(&self) -> Option<crate::control::HostIdentity> {
        self.hosted.then(|| crate::control::HostIdentity {
            version: crate::state::QSHD_VERSION.to_owned(),
            build: crate::state::build_label(),
            revision: crate::state::HOST_REVISION,
        })
    }

    fn replaced(&self) -> Option<FrontendIdentity> {
        // Plain data: a panic elsewhere cannot leave it half-written.
        self.replaced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[derive(Clone, Debug)]
pub struct RunningServerInfo {
    pub public_key: [u8; 32],
    pub serving: Arc<Serving>,
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
    /// The serving frontend's server information, refused when it would not
    /// fit the in-band encoding.
    pub fn info(&self) -> Result<ServerInfo> {
        let info = self.serving.server_info();
        transport::bootstrap::encode_server_info(&info)?;
        Ok(info)
    }

    pub fn response(&self, challenge: [u8; 32]) -> Result<String> {
        let info = self.info()?;
        let response = Response {
            challenge: hex::encode(challenge),
            server_pubkey: hex::encode(self.public_key),
            generation: hex::encode(info.generation),
            core_version: info.core_version,
            session_protocols: info
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
        let serving = Serving::own(false);
        serving.set(FrontendIdentity {
            version: "0.5.9".into(),
            build: 1,
            checksum: "ab".repeat(32),
            profiles: info.session_protocols.clone(),
            generation: info.generation,
        });
        let running = RunningServerInfo {
            public_key: [3; 32],
            serving,
        };
        let response: Response = serde_json::from_str(&running.response([8; 32]).unwrap()).unwrap();
        assert_eq!(response.core_version, "0.5.9");
        assert_eq!(response.challenge, hex::encode([8; 32]));
        assert_eq!(response.server_pubkey, hex::encode([3; 32]));
    }

    #[test]
    fn a_serving_describes_this_binary_until_another_frontend_is_set() {
        let serving = Serving::own(false);
        let own = serving.identity().unwrap();
        assert_eq!(
            own,
            FrontendIdentity {
                version: crate::state::QSHD_VERSION.into(),
                build: crate::state::build_label(),
                checksum: crate::state::self_checksum().unwrap(),
                profiles: current().session_protocols,
                generation: current().generation,
            }
        );
        assert_eq!(serving.host(), None);
        let other = FrontendIdentity {
            version: "9.0.0".into(),
            build: 9,
            checksum: "cd".repeat(32),
            profiles: Vec::new(),
            generation: [9; 16],
        };
        serving.set(other.clone());
        assert_eq!(serving.identity().unwrap(), other);
        assert_eq!(serving.generation(), [9; 16]);
        assert_eq!(
            Serving::own(true).host(),
            Some(crate::control::HostIdentity {
                version: crate::state::QSHD_VERSION.into(),
                build: crate::state::build_label(),
                revision: crate::state::HOST_REVISION,
            })
        );
    }
}
