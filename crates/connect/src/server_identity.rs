//! Public identities used to bind SSH recovery to an authenticated QSH server.
//! These types contain public keys only, never private keys or session tokens.

/// The QSH server and remote account authorized for recovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerIdentity {
    pub qsh_key: [u8; 32],
    pub username: String,
}

/// An SSH endpoint authorized for a server identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshEndpoint {
    pub host: String,
    pub port: u16,
}

/// An explicitly authorized association between QSH and SSH public identities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshBinding {
    pub server: ServerIdentity,
    pub endpoint: SshEndpoint,
    /// SSH host public key in wire format.
    pub host_key: Vec<u8>,
}
