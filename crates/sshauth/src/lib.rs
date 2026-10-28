//! Everything that knows what an SSH key is: parsing, signing and verifying
//! the proofs the transport carries.
//!
//! It lives apart from `crates/transport` so the transport can stay ignorant
//! of SSH key formats. Clients use its signers, key discovery and host-key
//! verification; the daemon uses the same record parsing and verification.

pub mod addr;
pub mod agent;
pub mod discover;
pub mod keyfile;
pub mod known_hosts;
mod native_rsa;
mod personal_authorized_keys;
pub mod prepared_key;
pub mod record;
pub mod route;
pub mod sign_file;
pub mod verify;

use transport::auth::{AuthError, AuthV2, AUTH_NONCE_LEN};

/// The version 2 fields for a record, or `None` when the server issued no
/// nonce and a version 1 record is what it expects. Fails when a nonce did
/// arrive but this signer has no login configured: silently dropping to
/// version 1 there would hand a system-mode server a record it must refuse,
/// and the user would see an unexplained rejection.
pub fn v2_fields(
    login: Option<&str>,
    nonce: Option<&[u8; AUTH_NONCE_LEN]>,
) -> Result<Option<AuthV2>, AuthError> {
    match nonce {
        None => Ok(None),
        Some(nonce) => {
            let login = login.ok_or_else(|| {
                AuthError::Backend(
                    "the server asked for a version 2 proof, but no login name is \
                     configured for this signer"
                        .to_string(),
                )
            })?;
            Ok(Some(AuthV2 {
                login: login.to_string(),
                nonce: *nonce,
            }))
        }
    }
}
