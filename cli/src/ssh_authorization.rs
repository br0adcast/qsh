//! Foreground, explicit association of an authenticated QSH peer and SSH key.
use crate::{
    climb::Setup,
    ssh_bindings::{BindingError, TrustWritePermit},
    ssh_step::{judge_host_key, HostKeyVerdict},
};
use connect::server_identity::{ServerIdentity, SshBinding, SshEndpoint};
use std::{fmt, sync::Arc};

#[derive(Debug)]
pub enum AuthorizationError {
    Cancelled,
    NoEndpoint,
    Verification(String),
    Store(BindingError),
}
impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("SSH authorization cancelled"),
            Self::NoEndpoint => f.write_str("no permitted SSH endpoint"),
            Self::Verification(why) => write!(f, "SSH verification: {why}"),
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for AuthorizationError {}
fn check(cancel: &knock::Cancel, permit: &TrustWritePermit) -> Result<(), AuthorizationError> {
    if cancel.is_cancelled() || crate::signals::termination_requested() {
        permit.invalidate();
        Err(AuthorizationError::Cancelled)
    } else {
        permit
            .ensure_active()
            .map_err(|_| AuthorizationError::Cancelled)
    }
}
fn verification(error: ssh::SshError) -> AuthorizationError {
    match error {
        ssh::SshError::Cancelled => AuthorizationError::Cancelled,
        other => AuthorizationError::Verification(other.to_string()),
    }
}
fn authenticated(server: &ServerIdentity, setup: &Setup) -> Result<(), AuthorizationError> {
    if setup.server_identity().as_ref() == Some(server) {
        Ok(())
    } else {
        Err(AuthorizationError::Verification(
            "QSH server has not authenticated this session".into(),
        ))
    }
}
/// Runs on the foreground thread before raw mode. It performs only host KEX,
/// never user authentication, remote commands, daemon lookup or installation.
/// Declining either question leaves the live QSH session intact.
pub fn authorize_ssh(
    server: &ServerIdentity,
    endpoints: &[SshEndpoint],
    setup: &Setup,
    permit: &TrustWritePermit,
    cancel: &knock::Cancel,
) -> Result<(), AuthorizationError> {
    if endpoints.is_empty() {
        return Err(AuthorizationError::NoEndpoint);
    }
    authenticated(server, setup)?;
    crate::signals::with_termination_cancel(cancel, || {
        let mut failure = None;
        for endpoint in endpoints {
            check(cancel, permit)?;
            match authorize_endpoint(server, endpoint, setup, permit, cancel) {
                Err(AuthorizationError::Cancelled) => {
                    permit.invalidate();
                    return Err(AuthorizationError::Cancelled);
                }
                Err(error) => failure = Some(error),
                Ok(()) => {}
            }
        }
        failure.map_or(Ok(()), Err)
    })
}
fn authorize_endpoint(
    server: &ServerIdentity,
    endpoint: &SshEndpoint,
    setup: &Setup,
    permit: &TrustWritePermit,
    cancel: &knock::Cancel,
) -> Result<(), AuthorizationError> {
    let mut params = setup
        .ssh_verification_params(endpoint)
        .ok_or(AuthorizationError::NoEndpoint)?;
    let keys = setup.ssh_hosts().lookup(&endpoint.host, endpoint.port);
    let info = match ssh::verify_host(params.clone(), Arc::new(knock::NoBind), cancel) {
        Ok(info) => info,
        Err(error) => {
            let name = crate::known_hosts::entry_name(&endpoint.host, endpoint.port);
            let info = match judge_host_key(&error, &keys, &name, setup.ssh_hosts()) {
                HostKeyVerdict::Ask(info) => info,
                HostKeyVerdict::Refuse(why) => return Err(AuthorizationError::Verification(why)),
                HostKeyVerdict::NotAboutTheKey => return Err(verification(error)),
            };
            let crate::ssh_step::UnknownHostKey::Ask(question) =
                crate::ssh_step::unknown_host_key(false, &name, &info)
            else {
                unreachable!()
            };
            if !setup
                .tty()
                .confirm_cancellable(&question, cancel)
                .map_err(verification)?
            {
                return Ok(());
            }
            check(cancel, permit)?;
            // A host accepted for this probe still needs its own successful KEX.
            // This append is separate ordinary SSH consent, but must still
            // serialize with cancellation/epoch invalidation. The closure
            // does not acquire the binding file lock or re-enter the permit.
            permit
                .write_if_active(cancel, || {
                    setup
                        .ssh_hosts()
                        .add(&endpoint.host, endpoint.port, &info.key_type, &info.key)
                })
                .map_err(|error| match error {
                    BindingError::Cancelled => AuthorizationError::Cancelled,
                    other => AuthorizationError::Store(other),
                })?;
            params.known_host_keys.push(info.key);
            ssh::verify_host(params, Arc::new(knock::NoBind), cancel).map_err(verification)?
        }
    };
    offer_binding(server, endpoint, &info, setup, permit, cancel)
}
/// Offer the exact host key of the successful initial bootstrap only after
/// the QSH connection has authenticated its independent expected server key.
pub fn offer_binding(
    server: &ServerIdentity,
    endpoint: &SshEndpoint,
    info: &ssh::HostKeyInfo,
    setup: &Setup,
    permit: &TrustWritePermit,
    cancel: &knock::Cancel,
) -> Result<(), AuthorizationError> {
    check(cancel, permit)?;
    authenticated(server, setup)?;
    let store = setup.ssh_bindings();
    if store
        .allowed(server, endpoint)
        .map_err(AuthorizationError::Store)?
        .contains(&info.key)
    {
        return Ok(());
    }
    let question = crate::report::ssh_authorization(server, endpoint, info);
    if !setup
        .tty()
        .confirm_cancellable(&question, cancel)
        .map_err(verification)?
    {
        return Ok(());
    }
    check(cancel, permit)?;
    // Re-read after consent: a key revoked while the prompt was open is refused.
    let keys = setup.ssh_hosts().lookup(&endpoint.host, endpoint.port);
    if !keys.known.contains(&info.key) || keys.revoked.contains(&info.key) {
        return Err(AuthorizationError::Verification(
            "SSH host key is no longer trusted in known_hosts".into(),
        ));
    }
    store
        .grant_cancellable(
            &SshBinding {
                server: server.clone(),
                endpoint: endpoint.clone(),
                host_key: info.key.clone(),
            },
            permit,
            cancel,
        )
        .map_err(|e| match e {
            BindingError::Cancelled => AuthorizationError::Cancelled,
            other => AuthorizationError::Store(other),
        })
}
