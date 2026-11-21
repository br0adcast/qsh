//! The images a host starts frontends and owners from (#529 M2): each held by
//! descriptor, with what the host knows of it, and the word a frontend
//! sends once it serves.

use std::sync::Arc;

use crate::owner_process::SelfImage;
use crate::server_info::FrontendIdentity;

/// What an image serves as: what its frontends answer clients with.
pub(crate) enum ImageIdentity {
    /// This binary, under this process's generation, as
    /// [`crate::server_info::Serving::own`] describes it. The rest of its
    /// identity is the one `Serving` hashes when first asked: a host never
    /// hashes its own image at start.
    Own { generation: [u8; 16] },
    /// Another image, as the host verified it, under the generation minted
    /// for it.
    // Not built until the frontend upgrade (#529 M2) is in.
    #[cfg_attr(not(test), allow(dead_code))]
    Known(FrontendIdentity),
}

impl ImageIdentity {
    /// The generation the image's frontends answer with.
    pub(crate) fn generation(&self) -> [u8; 16] {
        match self {
            ImageIdentity::Own { generation } => *generation,
            ImageIdentity::Known(identity) => identity.generation,
        }
    }
}

/// What the host knows of an image it starts frontends and owners from.
pub(crate) struct ImageInfo {
    pub(crate) identity: ImageIdentity,
    /// Its [`crate::state::HOST_REVISION`].
    // Not read until the frontend upgrade (#529 M2) is in.
    #[allow(dead_code)]
    pub(crate) host_revision: u32,
    /// The owner link versions it speaks, and so every owner started from
    /// it.
    pub(crate) link_versions: Vec<u16>,
    /// The session profiles `[wire, handshake, channel]` its frontends
    /// serve clients with.
    pub(crate) profiles: Vec<[u8; 3]>,
}

impl ImageInfo {
    /// This binary's, under the generation [`crate::server_info::current`]
    /// names -- the one `Serving::own` names too.
    pub(super) fn own() -> ImageInfo {
        let info = crate::server_info::current();
        ImageInfo {
            identity: ImageIdentity::Own {
                generation: info.generation,
            },
            host_revision: crate::state::HOST_REVISION,
            link_versions: vec![transport::OWNER_LINK_VERSION],
            profiles: info
                .session_protocols
                .iter()
                .map(|p| [p.wire, p.handshake, p.channel])
                .collect(),
        }
    }
}

/// An image the host starts frontends and owners from: held by descriptor
/// since it was opened, never by path, with what the host knows of it.
pub(crate) struct FrontendImage {
    pub(crate) image: SelfImage,
    pub(crate) info: Arc<ImageInfo>,
}

/// Whether one frontend process has said that it serves (`Ready`). A
/// replacement of the frontend waits for it; nothing else does.
pub(crate) struct Readiness(tokio::sync::watch::Sender<bool>);

impl Default for Readiness {
    fn default() -> Readiness {
        Readiness(tokio::sync::watch::Sender::new(false))
    }
}

impl Readiness {
    pub(super) fn report(&self) {
        self.0.send_replace(true);
    }

    /// Returns once the frontend has said that it serves, at once if it
    /// already has. A frontend that never says so leaves this pending: the
    /// caller bounds the wait.
    // Not awaited until the frontend upgrade (#529 M2) is in.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn reported(&self) {
        // The sender is `self`: it cannot close while this waits.
        let _ = self.0.subscribe().wait_for(|ready| *ready).await;
    }
}
