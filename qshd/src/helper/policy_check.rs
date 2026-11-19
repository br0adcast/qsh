//! Dormant system host-policy adapter inside the existing single-threaded
//! helper server. No helper/host wire request or runtime route is added.
//! Results and key capabilities are sealed here; logical consumer lifetime
//! never owns or releases the separately retained VerificationChild.
use super::*;
use crate::session_owner::authorization::{PolicyIntent, PolicyKind, PolicyResult, SystemContext};
use std::sync::{mpsc::SyncSender, Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostPolicyError {
    Refused,
}

struct VerifiedKey {
    context: SystemContext,
    uid: Uid,
    name: String,
    public_key: Vec<u8>,
}
/// Host-held proof of the exact verified key/account binding. The Arc is an
/// internal capability, not serialized authority or a cache of policy verdicts.
#[derive(Clone)]
pub(crate) struct SystemCredential(Arc<VerifiedKey>);
impl std::fmt::Debug for SystemCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SystemCredential([REDACTED])")
    }
}
impl SystemCredential {
    pub(crate) fn context(&self) -> SystemContext {
        self.0.context
    }
    pub(crate) fn same_registration(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    fn login(&self) -> &str {
        &self.0.name
    }
    /// Runs only under the common fork_verification descriptor/parent/mask
    /// boundary. Re-resolve and reread, without signature/nonce/login/PAM work.
    pub(super) fn check_current(
        &self,
        config: &HelperConfig,
        switches: AccountSwitches,
        verifier_parent: Option<authorized::VerifierParent>,
    ) -> Result<(Account, String, String), VerifyRefusal> {
        let account = (switches.lookup)(&self.0.name)
            .map_err(|e| VerifyRefusal::other(format!("account lookup: {e}")))?;
        if account.uid != self.0.uid || account.name != self.0.name {
            return Err(VerifyRefusal::other("canonical account changed"));
        }
        if root_refused(config, &account) {
            return Err(VerifyRefusal::other(
                "root login refused: permit_root is off",
            ));
        }
        let key = sshauth::record::decode_public_key(&self.0.public_key)
            .map_err(|e| VerifyRefusal::other(format!("retained key: {e}")))?;
        let text =
            (switches.read_keys)(&account, &config.authorized_keys_template, verifier_parent)
                .map_err(|e| VerifyRefusal::other(format!("reading authorized_keys: {e}")))?;
        if !sshauth::verify::key_is_listed(&text, &key)
            .map_err(|e| VerifyRefusal::other(format!("matching authorized_keys: {e}")))?
        {
            return Err(VerifyRefusal::other("key not listed"));
        }
        Ok((
            account,
            sshauth::verify::fingerprint(&key),
            sshauth::verify::algorithm_label(&key).to_string(),
        ))
    }
}

/// Constructed only on the parent-selected HostPolicy destination after the
/// common isolated verifier publishes an admitted, bounded report.
pub(crate) struct SystemPolicyApproval {
    account: Account,
    credential: SystemCredential,
}
impl SystemPolicyApproval {
    pub(crate) fn into_parts(self) -> (u32, String, SystemCredential) {
        (
            self.account.uid.as_raw(),
            self.account.name,
            self.credential,
        )
    }
}

/// One exact parent-issued nonce and its host/frontend/attempt/operation intent.
/// The frontend may observe nonce(), but cannot construct or clone this ticket.
pub(super) struct HostNonceTicket {
    intent: PolicyIntent,
    nonce: Nonce,
}
impl std::fmt::Debug for HostNonceTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostNonceTicket([REDACTED])")
    }
}
impl HostNonceTicket {
    pub(super) fn nonce(&self) -> Nonce {
        self.nonce
    }
}

pub(super) struct HostProof {
    pub(super) record: AuthRecord,
    pub(super) handshake_hash: [u8; 32],
}

enum DestinationWork {
    Authenticate(Vec<u8>),
    CurrentPolicy(SystemCredential),
}
pub(in crate::helper) struct HostPolicyDestination {
    intent: PolicyIntent,
    context: SystemContext,
    work: DestinationWork,
    reply: SyncSender<PolicyResult>,
}
impl HostPolicyDestination {
    pub(super) fn publish(self, verdict: Option<Verdict>) {
        let observation = match verdict {
            Some(Verdict::Admitted { account, .. }) => {
                let credential = match self.work {
                    DestinationWork::Authenticate(public_key) => {
                        SystemCredential(Arc::new(VerifiedKey {
                            context: self.context,
                            uid: account.uid,
                            name: account.name.clone(),
                            public_key,
                        }))
                    }
                    DestinationWork::CurrentPolicy(credential)
                        if credential.0.uid == account.uid && credential.0.name == account.name =>
                    {
                        credential
                    }
                    DestinationWork::CurrentPolicy(_) => {
                        let _ = self
                            .reply
                            .try_send(PolicyResult::system_refusal(self.intent));
                        return;
                    }
                };
                PolicyResult::from_system(
                    self.intent,
                    SystemPolicyApproval {
                        account,
                        credential,
                    },
                )
            }
            _ => PolicyResult::system_refusal(self.intent),
        };
        // Bounded and nonblocking. A cancelled/full consumer cannot retain a key
        // registration through this result, or free physical verifier custody.
        let _ = self.reply.try_send(observation);
    }
}

pub(super) fn issue_nonce_for_host(
    state: &mut LoopState,
    intent: PolicyIntent,
    now: u64,
) -> Result<HostNonceTicket, HostPolicyError> {
    if state.stopping
        || state.required_publication.is_some()
        || intent.kind() != PolicyKind::Authenticate
        || intent.system_context().is_none()
        || intent.deadline() <= now
    {
        return Err(HostPolicyError::Refused);
    }
    let nonce =
        issue_scoped_nonce(state, NonceDestination::HostPolicy).ok_or(HostPolicyError::Refused)?;
    Ok(HostNonceTicket { intent, nonce })
}
fn refuse(intent: PolicyIntent, reply: SyncSender<PolicyResult>) -> Result<(), HostPolicyError> {
    let _ = reply.try_send(PolicyResult::system_refusal(intent));
    Err(HostPolicyError::Refused)
}
fn admission_open(state: &LoopState) -> bool {
    !state.stopping
        && state.required_publication.is_none()
        && state.pending.verifying() < MAX_VERIFYING
}
fn deadline(intent: &PolicyIntent, now: u64) -> Option<Instant> {
    let remaining = intent.deadline().checked_sub(now).filter(|r| *r > 0)?;
    Instant::now().checked_add(Duration::from_millis(remaining))
}
fn install(
    state: &mut LoopState,
    start: VerificationStart,
    login: String,
    destination: HostPolicyDestination,
) {
    let VerificationStart {
        report,
        child,
        deadline,
        #[cfg(target_os = "linux")]
        custody,
    } = start;
    state.pending.insert(Pending {
        deadline,
        what: PendingWhat::Verify {
            report,
            child,
            answered: false,
            #[cfg(target_os = "linux")]
            custody: Some(Box::new(custody)),
            login: sanitized_login_name(&login),
            destination: VerificationDestination::HostPolicy(Some(Box::new(destination))),
        },
    });
}
#[allow(clippy::too_many_arguments)] // Existing server context, owned proof and bounded reply destination.
pub(super) fn start_authentication(
    state: &mut LoopState,
    ticket: HostNonceTicket,
    proof: HostProof,
    reply: SyncSender<PolicyResult>,
    config: &HelperConfig,
    switches: AccountSwitches,
    now: u64,
) -> Result<(), HostPolicyError> {
    let HostNonceTicket { intent, nonce } = ticket;
    // Preserve the shared cap-before-spend rule, including answered/unjoined
    // native verification debt. No fresh nonce can bypass that physical cap.
    if !admission_open(state) {
        return refuse(intent, reply);
    }
    if spend_nonce(&mut state.host_nonces, &nonce, Instant::now()).is_err() {
        return refuse(intent, reply);
    }
    let Some(context) = intent.system_context() else {
        return refuse(intent, reply);
    };
    let Some(deadline) = deadline(&intent, now) else {
        return refuse(intent, reply);
    };
    let Some(v2) = proof.record.v2.as_ref() else {
        return refuse(intent, reply);
    };
    if intent.kind() != PolicyKind::Authenticate
        || v2.nonce != nonce
        || v2.login.len() > transport::auth::AUTH_LOGIN_MAX
        || v2.login.is_empty()
        || v2.login.contains(['\0', '/'])
        || proof.record.public_key.len() > super::super::protocol::MAX_MESSAGE_LEN
        || proof.record.signature.len() > super::super::protocol::MAX_MESSAGE_LEN
    {
        return refuse(intent, reply);
    }
    // Reuse the existing proof envelope's exact 8KiB ceiling, solely as an
    // internal bounds check. This JSON is neither sent nor called QSHH authority.
    let bounded = Request::Verify {
        login: v2.login.clone(),
        public_key: proof.record.public_key.clone(),
        signature: proof.record.signature.clone(),
        handshake_hash: proof.handshake_hash,
        nonce,
        login_id: [0; 16],
        rhost: String::new(),
    };
    if encode(&bounded).is_err() {
        return refuse(intent, reply);
    }
    let work = VerificationWork::Authenticate {
        login: &v2.login,
        public_key: &proof.record.public_key,
        signature: &proof.record.signature,
        handshake_hash: &proof.handshake_hash,
        nonce: &nonce,
    };
    match fork_verification_work(
        work,
        config,
        switches,
        #[cfg(target_os = "linux")]
        state.child_mask,
        Some(deadline),
    ) {
        Ok(start) => {
            install(
                state,
                start,
                v2.login.clone(),
                HostPolicyDestination {
                    intent,
                    context,
                    work: DestinationWork::Authenticate(proof.record.public_key),
                    reply,
                },
            );
            Ok(())
        }
        Err(_) => refuse(intent, reply),
    }
}
pub(super) fn start_policy_check(
    state: &mut LoopState,
    intent: PolicyIntent,
    reply: SyncSender<PolicyResult>,
    config: &HelperConfig,
    switches: AccountSwitches,
    now: u64,
) -> Result<(), HostPolicyError> {
    if !admission_open(state)
        || !matches!(
            intent.kind(),
            PolicyKind::IssueGrant | PolicyKind::ConsumeGrant
        )
    {
        return refuse(intent, reply);
    }
    let Some(context) = intent.system_context() else {
        return refuse(intent, reply);
    };
    let Some(deadline) = deadline(&intent, now) else {
        return refuse(intent, reply);
    };
    let Some(credential) = intent
        .system_credential()
        .filter(|c| c.context() == context)
        .cloned()
    else {
        return refuse(intent, reply);
    };
    match fork_verification_work(
        VerificationWork::CurrentPolicy(&credential),
        config,
        switches,
        #[cfg(target_os = "linux")]
        state.child_mask,
        Some(deadline),
    ) {
        Ok(start) => {
            let login = credential.login().to_string();
            install(
                state,
                start,
                login,
                HostPolicyDestination {
                    intent,
                    context,
                    work: DestinationWork::CurrentPolicy(credential),
                    reply,
                },
            );
            Ok(())
        }
        Err(_) => refuse(intent, reply),
    }
}

/// Cancels an unsubmitted ticket without granting authority or touching a child.
pub(super) fn cancel_nonce_for_host(
    state: &mut LoopState,
    ticket: HostNonceTicket,
) -> PolicyIntent {
    state.host_nonces.remove(&ticket.nonce);
    ticket.intent
}
#[cfg(test)]
impl HostNonceTicket {
    pub(super) fn duplicate_for_test(&self) -> Self {
        Self {
            intent: self.intent.copy_for_test(),
            nonce: self.nonce,
        }
    }
}
#[cfg(test)]
impl HostPolicyDestination {
    pub(super) fn refusal_for_test(intent: PolicyIntent, reply: SyncSender<PolicyResult>) -> Self {
        Self {
            context: intent.system_context().unwrap(),
            intent,
            work: DestinationWork::Authenticate(Vec::new()),
            reply,
        }
    }
}
