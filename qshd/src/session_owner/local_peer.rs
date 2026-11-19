//! The sole inherited-channel bridge into sealed frontend peer authority.
use super::{AuthenticatedPeer, AuthorityError, HostMode};
use crate::session_owner::local_channel::AdmittedChannel;
pub(crate) fn authenticate_frontend(
    channel: &mut AdmittedChannel,
    mode: HostMode,
) -> Result<AuthenticatedPeer, AuthorityError> {
    let (host, mode) = channel.take_frontend_evidence(mode)?;
    Ok(AuthenticatedPeer { host, mode })
}
