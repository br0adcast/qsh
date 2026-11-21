//! Authenticated session reset (#529): how a daemon tells a client at once
//! that the connection it uses is gone, in the manner of QUIC's stateless
//! reset (RFC 9000 §10.3).
//!
//! When both peers negotiate `session-reset` ([`crate::Features::SESSION_RESET`]),
//! the encrypted msg2 gives the client a token for its connection:
//! `HMAC-SHA256(secret, "qsh/session-reset/v1" || session_id_be)[..16]`
//! ([`SessionResetSecret::token`]). The secret belongs to the daemon's host
//! process, not to the network frontend, and lives beside the static key:
//! every frontend the host starts, and the daemon after a restart, derives
//! the same token for the same `session_id`.
//!
//! A frontend that receives a `Transport` datagram for a `session_id` it
//! does not route answers with a `SessionReset` datagram
//! (`crate::wire::encode_session_reset`) carrying the token it derives for
//! that id -- held to a rate per source and in all ([`ResetResponder`]),
//! and never larger than the datagram it answers. The client whose
//! connection carries that `session_id` and that token lets the connection
//! go without a word and returns warm; any other reset is ignored. Nobody
//! without the secret can make a token, and a token is sent in the clear
//! only once its connection is gone.

use std::fmt;
#[cfg(feature = "tokio-driver")]
use std::net::SocketAddr;
#[cfg(feature = "tokio-driver")]
use std::time::Instant;

use hmac::{KeyInit, Mac};
use zeroize::Zeroizing;

#[cfg(feature = "tokio-driver")]
use crate::cookie::{bucket_of, Budget, SourceRate};
#[cfg(feature = "tokio-driver")]
use crate::wire;

/// The host's secret: 32 random bytes.
pub const SESSION_RESET_SECRET_LEN: usize = 32;

/// A connection's token, in msg2 and in its reset.
pub const SESSION_RESET_TOKEN_LEN: usize = 16;

/// The domain of the token's MAC.
const LABEL: &[u8] = b"qsh/session-reset/v1";

/// Resets one source may be sent a second once its burst is spent, and that
/// burst. A client needs one: it lets its connection go on the first. A
/// handful covers several clients behind one address that all lost their
/// frontend at the same moment, and a lost reset is answered again on the
/// client's next datagram (a PING is never more than 1.5 s away).
pub const RESETS_PER_SOURCE_PER_SECOND: u32 = 10;

/// See [`RESETS_PER_SOURCE_PER_SECOND`].
pub const RESET_SOURCE_BURST: u32 = 10;

/// Resets the daemon sends a second in all once its burst is spent, and
/// that burst: every session the daemon can hold
/// (`session_manager::MAX_SESSIONS_TOTAL`) hears its reset within the first
/// second after a frontend restart, and a flood of forged sources costs no
/// more than that.
pub const RESETS_PER_SECOND: u32 = 128;

/// See [`RESETS_PER_SECOND`].
pub const RESET_BURST: u32 = 128;

/// Sources the per-source table holds at once; a new one past that gets no
/// reset until the table is swept (`cookie::SourceRate`).
pub const RESET_RATE_SOURCES: usize = 1024;

/// Bit 63 of the `session_id` a daemon mints for a connection says whether
/// that connection negotiated `session-reset`; the other 63 bits are random.
/// A frontend that does not know a connection answers only an id with this
/// bit set, so a client that never negotiated the reset is never sent one.
pub const RESET_SESSION_BIT: u64 = 1 << 63;

/// The `session_id` for a connection: `random` with [`RESET_SESSION_BIT`]
/// set exactly when it negotiated `session-reset`.
pub(crate) fn session_id_for(random: u64, reset: bool) -> u64 {
    if reset {
        random | RESET_SESSION_BIT
    } else {
        random & !RESET_SESSION_BIT
    }
}

/// The secret a daemon's host derives every reset token from. Wiped on drop;
/// deliberately not printable.
#[derive(Clone)]
pub struct SessionResetSecret(Zeroizing<[u8; SESSION_RESET_SECRET_LEN]>);

impl SessionResetSecret {
    /// The secret these bytes are (as read back from where it is kept).
    pub fn from_bytes(bytes: [u8; SESSION_RESET_SECRET_LEN]) -> SessionResetSecret {
        SessionResetSecret(Zeroizing::new(bytes))
    }

    /// A new secret, straight from the operating system's randomness (for
    /// the reason `auth::random_nonce` gives: the daemon forks).
    pub fn generate() -> std::io::Result<SessionResetSecret> {
        let mut bytes = Zeroizing::new([0u8; SESSION_RESET_SECRET_LEN]);
        getrandom::fill(&mut bytes[..]).map_err(std::io::Error::other)?;
        Ok(SessionResetSecret(bytes))
    }

    /// The bytes, for whoever keeps or hands the secret on.
    pub fn expose(&self) -> &[u8; SESSION_RESET_SECRET_LEN] {
        &self.0
    }

    /// The token of the connection `session_id`:
    /// `HMAC-SHA256(secret, "qsh/session-reset/v1" || session_id_be)[..16]`.
    pub fn token(&self, session_id: u64) -> [u8; SESSION_RESET_TOKEN_LEN] {
        let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&self.0[..])
            .expect("HMAC takes a key of any length");
        mac.update(LABEL);
        mac.update(&session_id.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        let mut token = [0u8; SESSION_RESET_TOKEN_LEN];
        token.copy_from_slice(&tag[..SESSION_RESET_TOKEN_LEN]);
        token
    }
}

impl fmt::Debug for SessionResetSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionResetSecret(..)")
    }
}

/// Whether two tokens are the same, in time that does not depend on where
/// they differ.
pub(crate) fn tokens_match(
    a: &[u8; SESSION_RESET_TOKEN_LEN],
    b: &[u8; SESSION_RESET_TOKEN_LEN],
) -> bool {
    subtle::ConstantTimeEq::ct_eq(&a[..], &b[..]).into()
}

/// What a frontend answers a connection it does not route with: the secret,
/// and the budgets that hold the answers back.
#[cfg(feature = "tokio-driver")]
pub(crate) struct ResetResponder {
    secret: SessionResetSecret,
    sources: SourceRate,
    all: Budget,
}

#[cfg(feature = "tokio-driver")]
impl ResetResponder {
    pub(crate) fn new(secret: SessionResetSecret, now: Instant) -> ResetResponder {
        ResetResponder {
            secret,
            sources: SourceRate::new(
                now,
                RESETS_PER_SOURCE_PER_SECOND,
                RESET_SOURCE_BURST,
                RESET_RATE_SOURCES,
            ),
            all: Budget::full(now, bucket_of(RESETS_PER_SECOND, RESET_BURST).1),
        }
    }

    pub(crate) fn secret(&self) -> &SessionResetSecret {
        &self.secret
    }

    /// The reset for a `Transport` datagram of `len` bytes from `src` naming
    /// `session_id`, which this frontend does not route -- or `None`: the id
    /// is not one of a connection that negotiated the reset
    /// ([`RESET_SESSION_BIT`]), the datagram is shorter than the reset (an
    /// answer never outweighs what it answers), or the source's or the
    /// daemon's budget is spent.
    pub(crate) fn answer(
        &mut self,
        now: Instant,
        src: SocketAddr,
        len: usize,
        session_id: u64,
    ) -> Option<Vec<u8>> {
        // Not a connection that negotiated the reset, or one this datagram
        // could not be (shorter than the answer): nothing, and no charge.
        if session_id & RESET_SESSION_BIT == 0
            || len < wire::SESSION_RESET_LEN
            || !self.sources.allow(now, src.ip())
        {
            return None;
        }
        let (cost, bucket) = bucket_of(RESETS_PER_SECOND, RESET_BURST);
        if !self.all.take(now, cost, bucket) {
            return None;
        }
        Some(wire::encode_session_reset(
            session_id,
            &self.secret.token(session_id),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token is the spec's formula, byte for byte: RFC 2104 HMAC over
    /// the label and the big-endian id, cut to its first 16 bytes.
    #[test]
    fn the_token_is_hmac_sha256_of_the_label_and_the_id() {
        use sha2::Digest;
        let secret = SessionResetSecret::from_bytes([0x42; 32]);
        let id = 0x0102_0304_0506_0708u64;
        // HMAC by hand: H((K ^ opad) || H((K ^ ipad) || m)), K padded to 64.
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&[0x42; 32]);
        let inner = sha2::Sha256::new()
            .chain_update(key.map(|b| b ^ 0x36))
            .chain_update(b"qsh/session-reset/v1")
            .chain_update([1, 2, 3, 4, 5, 6, 7, 8])
            .finalize();
        let outer = sha2::Sha256::new()
            .chain_update(key.map(|b| b ^ 0x5c))
            .chain_update(inner)
            .finalize();
        assert_eq!(secret.token(id)[..], outer[..16]);
        assert_ne!(secret.token(id), secret.token(id + 1));
        assert_ne!(
            secret.token(id),
            SessionResetSecret::from_bytes([0x43; 32]).token(id)
        );
        assert!(tokens_match(&secret.token(id), &secret.token(id)));
        assert!(!tokens_match(&secret.token(id), &secret.token(id + 1)));
        assert_eq!(format!("{secret:?}"), "SessionResetSecret(..)");
    }

    #[test]
    fn generated_secrets_differ() {
        let a = SessionResetSecret::generate().unwrap();
        let b = SessionResetSecret::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_eq!(
            crate::wire::SESSION_RESET_LEN,
            2 + 8 + SESSION_RESET_TOKEN_LEN
        );
    }
}
