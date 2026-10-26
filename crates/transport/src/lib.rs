//! Transport protocol core (sans-IO). Public version-assembly entry point.

pub mod auth;
pub mod auth_acceptance;
pub mod channel;
pub mod channel_geometry;
#[cfg(feature = "tokio-driver")]
mod channel_input;
#[cfg(feature = "tokio-driver")]
pub mod channel_open;
#[cfg(feature = "tokio-driver")]
mod channel_reply_delivery;
#[cfg(feature = "tokio-driver")]
pub mod channel_server;
pub mod channel_timeline;
pub mod client_input_budget;
mod client_input_queue;
mod congestion;
pub mod conn;
#[cfg(feature = "tokio-driver")]
mod control_budget;
#[cfg(feature = "tokio-driver")]
mod control_job;
pub mod cookie;
#[cfg(feature = "tokio-driver")]
mod dgram_queue;
pub mod driver_std;
#[cfg(feature = "tokio-driver")]
pub mod driver_tokio;
pub mod features;
pub mod handshake;
pub mod handshake_payload;
pub mod paths;
#[cfg(feature = "tokio-driver")]
pub mod probation;
#[cfg(feature = "tokio-driver")]
mod raw_admission;
pub mod recovery_handshake;
pub mod reliability;
mod rtt;
pub mod send_gate;
#[cfg(feature = "tokio-driver")]
pub mod session_manager;
pub mod shell_frame;
#[cfg(feature = "tokio-driver")]
pub mod shell_server;
#[cfg(test)]
mod sim_acks;
#[cfg(test)]
mod sim_cookie;
#[cfg(test)]
mod sim_credits;
#[cfg(test)]
mod sim_idle_traffic;
#[cfg(test)]
mod sim_negotiation;
#[cfg(test)]
mod sim_regressions;
#[cfg(any(test, feature = "testnet"))]
pub mod test_peer;
#[cfg(any(test, feature = "testnet"))]
pub mod testnet;
pub mod udp_buffers;
pub mod wire;

pub use auth::*;
pub use auth_acceptance::{
    encode_auth_acceptance, AuthAcceptance, AuthAcceptanceError, SessionDisposition,
};
pub use conn::*;
pub use handshake_payload::*;
pub use reliability::SessionAbortReason;
// The negotiable features (spec §5) are named by every layer that builds a
// connection or says what one agreed: `transport::Features`.
pub use features::Features;
// The session manager (and the canonical `SharedAllowlist`) live
// behind the async feature; re-export so `qshd` can `use transport::...`.
// `AUTH_DEADLINE` is NOT among them: it bounds the client's side of the
// exchange as much as the server's, so it lives in `auth` (re-exported
// unconditionally above) where a build without `tokio-driver` can see it.
#[cfg(feature = "tokio-driver")]
pub use session_manager::*;
// Key generation is needed both by the platform and by FFI boundary tests:
// re-export it from `handshake` at the crate root for a convenient
// `transport::generate_keypair`.
pub use handshake::generate_keypair;
// Socket buffer sizes (spec §4.12): every transport socket -- the daemon's,
// the app's, `qsh`'s -- asks for the same amount and reads back what it got.
pub use udp_buffers::{tune_udp_buffers, BufferReport, SOCKET_BUFFER_REQUEST};

/// Core version, for the platform side to verify.
pub fn version() -> &'static str {
    concat!("transport-core ", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_nonempty() {
        assert!(version().starts_with("transport-core "));
    }
}

#[cfg(feature = "tokio-driver")]
mod session_deadline;
