//! Logging in by a plan: passwords known or asked, keyboard-interactive,
//! private keys the app holds, agent keys and key files, a key that never
//! leaves the platform's key store and only signs -- tried in order, in one
//! connection.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PublicKey};
use russh::{MethodKind, MethodSet};

use crate::{
    keyfile, AuthMethod, AuthPrompter, EndSlot, Ended, ExternalSigner, Prompt, SshAuthPlan,
    SshError,
};

/// How long a login step that found the session gone waits for the handler
/// to say why, in `knock::SLICE`s: russh answers some steps before it has
/// told the handler (a refusal naming no method, a send into a session
/// already closing).
const ENDED_WAIT_SLICES: u32 = 4;

/// The longest part of a server's own goodbye that is passed on.
const SERVER_WORDS_MAX: usize = 200;

/// Time spent waiting for a person, so a network wait's deadline can leave it out.
#[derive(Clone, Default)]
pub(crate) struct PromptClock(Arc<std::sync::atomic::AtomicU64>);

impl PromptClock {
    /// Runs `ask` and books its duration.
    pub(crate) fn ask<T>(&self, ask: impl FnOnce() -> T) -> T {
        let started = std::time::Instant::now();
        let out = ask();
        self.0.fetch_add(
            started.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
        out
    }

    fn booked(&self) -> Duration {
        Duration::from_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// Runs `fut` until it ends, or until `limit` of time NOT spent in prompts
/// has passed. The prompter blocks this single-threaded runtime, so the
/// check only runs between prompts; that is enough, a prompt's own time is
/// subtracted afterwards.
pub(crate) async fn with_step_timeout<F: std::future::Future>(
    fut: F,
    limit: Duration,
    clock: &PromptClock,
) -> Option<F::Output> {
    let started = std::time::Instant::now();
    let booked_at_start = clock.booked();
    tokio::pin!(fut);
    loop {
        tokio::select! {
            out = &mut fut => return Some(out),
            _ = tokio::time::sleep(knock::SLICE) => {
                let waited = started
                    .elapsed()
                    .saturating_sub(clock.booked() - booked_at_start);
                if waited > limit {
                    return None;
                }
            }
        }
    }
}

/// What one attempt came to.
enum Attempt {
    Success,
    /// The server said no, or accepted a factor and wants another; either
    /// way `remaining` is what it takes next.
    Refused {
        remaining: MethodSet,
    },
    /// Not tried: no answer from the prompter, no agent, an unreadable file.
    Skipped(String),
    /// The same key was already offered; not worth a word.
    Duplicate,
    /// The session is over: the server hung up or the network went. Why is
    /// read from the handler's `EndSlot`.
    Gone,
}

pub(crate) struct Login<'a, H: russh::client::Handler> {
    pub handle: &'a mut Handle<H>,
    pub username: &'a str,
    pub host: &'a str,
    pub step_timeout: Duration,
    pub clock: PromptClock,
    pub cancel: knock::Cancel,
    pub ended: Arc<EndSlot>,
}

/// The deadline of one network wait, kept apart from the handle so a wait
/// can be built while the handle is borrowed.
struct Wait {
    host: String,
    step_timeout: Duration,
    clock: PromptClock,
    cancel: knock::Cancel,
}

impl Wait {
    async fn on<T>(&self, fut: impl std::future::Future<Output = T>) -> Result<T, SshError> {
        crate::with_cancel(
            with_step_timeout(fut, self.step_timeout, &self.clock),
            &self.cancel,
        )
        .await?
        .ok_or_else(|| {
            SshError::Connect(format!(
                "{} did not answer the login within {:?}",
                self.host, self.step_timeout
            ))
        })
    }
}

pub(crate) async fn authenticate<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    plan: SshAuthPlan,
) -> Result<(), SshError> {
    let mut allowed: Option<MethodSet> = None;
    let mut offered: std::collections::HashSet<Vec<u8>> = Default::default();
    let mut tried: Vec<&'static str> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for method in plan.methods {
        let kind = method_kind(&method);
        if matches!(method, AuthMethod::AskPassword) && allowed.is_none() {
            // Nobody is asked for a password the server would never take:
            // `none` learns its methods first (OpenSSH does not count it
            // against MaxAuthTries).
            match ask_for_methods(login).await? {
                Attempt::Success => return Ok(()),
                Attempt::Refused { remaining } => allowed = Some(remaining),
                // `answered` gives nothing else: the session is gone.
                _ => return Err(ended(login, &tried, &skipped).await),
            }
        }
        if let Some(a) = &allowed {
            if !a.contains(&kind) {
                continue;
            }
        }
        let attempts = run_method(login, method, &*plan.prompter, &mut offered).await?;
        for attempt in attempts {
            match attempt {
                Attempt::Success => return Ok(()),
                Attempt::Refused { remaining } => {
                    tried.push(kind_name(kind));
                    allowed = Some(remaining);
                }
                Attempt::Skipped(why) => skipped.push(why),
                Attempt::Duplicate => {}
                Attempt::Gone => {
                    tried.push(kind_name(kind));
                    return Err(ended(login, &tried, &skipped).await);
                }
            }
        }
    }
    Err(SshError::AuthFailed(refusal_text(
        &tried,
        &skipped,
        allowed.as_ref(),
    )))
}

/// The `none` request: logs in on a server that asks nothing, and otherwise
/// learns which methods it takes.
async fn ask_for_methods<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
) -> Result<Attempt, SshError> {
    let wait = Wait {
        host: login.host.to_string(),
        step_timeout: login.step_timeout,
        clock: login.clock.clone(),
        cancel: login.cancel.clone(),
    };
    answered(
        wait.on(login.handle.authenticate_none(login.username))
            .await?,
    )
}

/// The session ended during the login; the handler was told why. A server
/// that ended the login itself refused it. Anything else is a lost
/// connection, worth another try.
async fn ended<H: russh::client::Handler>(
    login: &Login<'_, H>,
    tried: &[&'static str],
    skipped: &[String],
) -> SshError {
    for slice in 0..=ENDED_WAIT_SLICES {
        if let Some(ended) = login.ended.take() {
            return match ended {
                Ended::ByServer(words) => SshError::AuthFailed(server_ended_text(&words)),
                Ended::NoMethod => SshError::AuthFailed(format!(
                    "the server accepts none of the methods tried ({})",
                    attempts_text(tried, skipped)
                )),
                Ended::Lost => lost(login.host),
            };
        }
        if slice < ENDED_WAIT_SLICES {
            tokio::time::sleep(knock::SLICE).await;
        }
    }
    lost(login.host)
}

fn lost(host: &str) -> SshError {
    SshError::Connect(format!("{host}: the connection was lost during login"))
}

/// `the server ended the login: Too many authentication failures`, the
/// server's words on one line and kept short.
fn server_ended_text(words: &str) -> String {
    let words: String = words
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(SERVER_WORDS_MAX)
        .collect();
    let words = words.trim();
    if words.is_empty() {
        "the server ended the login".into()
    } else {
        format!("the server ended the login: {words}")
    }
}

fn method_kind(method: &AuthMethod) -> MethodKind {
    match method {
        AuthMethod::Password(_) | AuthMethod::AskPassword => MethodKind::Password,
        AuthMethod::KeyboardInteractive => MethodKind::KeyboardInteractive,
        AuthMethod::PrivateKeyPem(_)
        | AuthMethod::Signer(_)
        | AuthMethod::Agent(_)
        | AuthMethod::KeyFile(_) => MethodKind::PublicKey,
    }
}

fn kind_name(kind: MethodKind) -> &'static str {
    match kind {
        MethodKind::Password => "password",
        MethodKind::KeyboardInteractive => "keyboard-interactive",
        _ => "publickey",
    }
}

/// Why the plan ended without a login: what was tried, what was skipped, or,
/// when nothing was either, what the server would have taken.
fn refusal_text(tried: &[&'static str], skipped: &[String], allowed: Option<&MethodSet>) -> String {
    if !tried.is_empty() {
        return format!(
            "the server refused the login ({})",
            attempts_text(tried, skipped)
        );
    }
    if !skipped.is_empty() {
        return format!(
            "no login method could be tried (skipped: {})",
            skipped.join(", ")
        );
    }
    match allowed {
        Some(allowed) => format!(
            "the server takes none of the methods in the plan (it offers: {})",
            allowed
                .iter()
                .map(<&'static str>::from)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None => "the plan has no login method".into(),
    }
}

/// `tried: publickey x3, password x1; skipped: ...`.
fn attempts_text(tried: &[&'static str], skipped: &[String]) -> String {
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for name in tried {
        match groups.iter_mut().find(|(n, _)| n == name) {
            Some((_, count)) => *count += 1,
            None => groups.push((name, 1)),
        }
    }
    let tried_text = groups
        .iter()
        .map(|(name, count)| format!("{name} x{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let skipped_text = if skipped.is_empty() {
        String::new()
    } else {
        format!("; skipped: {}", skipped.join(", "))
    };
    format!("tried: {tried_text}{skipped_text}")
}

/// A refusal that leaves nothing to try and accepts no factor is russh
/// reporting the session over: its reply channel closed, or the server
/// named no method russh knows (russh then ends the session itself).
fn refusal(remaining: MethodSet, partial: bool) -> Attempt {
    if remaining.is_empty() && !partial {
        Attempt::Gone
    } else {
        Attempt::Refused { remaining }
    }
}

fn outcome(result: AuthResult) -> Attempt {
    match result {
        AuthResult::Success => Attempt::Success,
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => refusal(remaining_methods, partial_success),
    }
}

/// A login step's answer, or the session gone.
fn answered(sent: Result<AuthResult, russh::Error>) -> Result<Attempt, SshError> {
    sent.map(outcome)
        .or_else(|e| session_gone(e).map(|()| Attempt::Gone))
}

/// The errors a login step of russh's `Handle` gives when the session is
/// no longer there to answer (`SendError`: it stopped taking requests;
/// `RecvError`: it dropped its replies; `Inconsistent`: it dropped a reply
/// it owed) are `Ok`: the caller reads the handler's reason. Anything else
/// is a fault of its own.
fn session_gone(e: russh::Error) -> Result<(), SshError> {
    match e {
        russh::Error::SendError | russh::Error::RecvError | russh::Error::Inconsistent => Ok(()),
        other => Err(SshError::Protocol(other.to_string())),
    }
}

async fn run_method<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    method: AuthMethod,
    prompter: &dyn AuthPrompter,
    offered: &mut std::collections::HashSet<Vec<u8>>,
) -> Result<Vec<Attempt>, SshError> {
    let username = login.username;
    let wait = Wait {
        host: login.host.to_string(),
        step_timeout: login.step_timeout,
        clock: login.clock.clone(),
        cancel: login.cancel.clone(),
    };
    let attempt = match method {
        AuthMethod::Password(password) => {
            let sent = wait
                .on(login
                    .handle
                    .authenticate_password(username, password.as_str()))
                .await?;
            answered(sent)?
        }
        AuthMethod::PrivateKeyPem(pem) => {
            let key = wait
                .on(crate::crypto_worker::run(move || {
                    keyfile::decode(&pem)
                        .and_then(|key| key.into_prepared(None).map_err(|e| e.to_string()))
                }))
                .await?
                .map_err(crypto_error)?
                .map_err(|e| {
                    SshError::AuthFailed(format!("the private key could not be read: {e}"))
                })?;
            offer_private_key(login, &wait, key, offered).await?
        }
        AuthMethod::Signer(signer) => {
            let wire = signer.public_key().map_err(|e| {
                SshError::AuthFailed(format!("no public key from the key store: {e}"))
            })?;
            let public = PublicKey::from_bytes(&wire).map_err(|e| {
                SshError::AuthFailed(format!("the key store's public key is invalid: {e}"))
            })?;
            if !offered.insert(canonical(&public)?) {
                return Ok(vec![Attempt::Duplicate]);
            }
            let Some(hash) = hash_for(login, &wait, &public).await? else {
                return Ok(vec![Attempt::Gone]);
            };
            let sent = wait
                .on(login.handle.authenticate_publickey_with(
                    username,
                    public,
                    hash,
                    &mut GuardedSigner {
                        signer: &mut SignerBridge(signer),
                        cancel: &wait.cancel,
                    },
                ))
                .await?;
            signed(sent)?
        }
        AuthMethod::Agent(socket) => return offer_agent_keys(login, &wait, &socket, offered).await,
        AuthMethod::KeyFile(path) => {
            let read_path = path.clone();
            let key = match wait
                .on(crate::crypto_worker::run(move || keyfile::read(&read_path)))
                .await?
                .map_err(crypto_error)?
            {
                Ok(key) => key,
                Err(why) => {
                    return Ok(vec![Attempt::Skipped(format!("{}: {why}", path.display()))])
                }
            };
            match key {
                sshauth::keyfile::DecodedKey::Prepared(key) => {
                    offer_private_key(login, &wait, key, offered).await?
                }
                sshauth::keyfile::DecodedKey::Locked(key) => {
                    return offer_locked_key(login, &wait, &path, &key, prompter, offered).await
                }
            }
        }
        AuthMethod::AskPassword => {
            let Some(password) = login.clock.ask(|| prompter.password(username, login.host)) else {
                return Ok(vec![Attempt::Skipped("password: no answer".into())]);
            };
            // russh takes its own `String` copy, which cannot be zeroed from here.
            let sent = wait
                .on(login
                    .handle
                    .authenticate_password(username, password.as_str()))
                .await?;
            answered(sent)?
        }
        AuthMethod::KeyboardInteractive => keyboard_interactive(login, &wait, prompter).await?,
    };
    Ok(vec![attempt])
}

/// Rounds of one keyboard-interactive attempt before it is given up: a
/// server that asks forever does not hold the login forever.
const KEYBOARD_INTERACTIVE_ROUNDS: usize = 10;

/// keyboard-interactive: every round with prompts goes to the prompter, a
/// round without prompts is answered empty without asking.
async fn keyboard_interactive<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    wait: &Wait,
    prompter: &dyn AuthPrompter,
) -> Result<Attempt, SshError> {
    let started = wait
        .on(login
            .handle
            .authenticate_keyboard_interactive_start(login.username, None::<String>))
        .await?;
    let mut reply = match started {
        Ok(reply) => reply,
        Err(e) => return session_gone(e).map(|()| Attempt::Gone),
    };
    let mut rounds = 0;
    loop {
        let (name, instructions, prompts) = match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(Attempt::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => return Ok(refusal(remaining_methods, partial_success)),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => (name, instructions, prompts),
        };
        if rounds == KEYBOARD_INTERACTIVE_ROUNDS {
            return Ok(Attempt::Skipped(
                "keyboard-interactive: too many rounds".into(),
            ));
        }
        rounds += 1;
        let prompts: Vec<Prompt> = prompts
            .into_iter()
            .map(|p| Prompt {
                text: p.prompt,
                echo: p.echo,
            })
            .collect();
        let answers = if prompts.is_empty() {
            Vec::new()
        } else {
            match login
                .clock
                .ask(|| prompter.keyboard_interactive(&name, &instructions, &prompts))
            {
                Some(answers) if answers.len() == prompts.len() => answers,
                _ => return Ok(Attempt::Skipped("keyboard-interactive: no answer".into())),
            }
        };
        // russh takes plain `String` copies, which cannot be zeroed from
        // here; `answers` itself is zeroed when it goes.
        let responses = answers.iter().map(|a| a.as_str().to_owned()).collect();
        let sent = wait
            .on(login
                .handle
                .authenticate_keyboard_interactive_respond(responses))
            .await?;
        reply = match sent {
            Ok(reply) => reply,
            Err(e) => return session_gone(e).map(|()| Attempt::Gone),
        };
    }
}

/// The one encoding every key source is compared in, so the same key from
/// an agent, a file and the key store is recognised as the same.
fn canonical(public: &PublicKey) -> Result<Vec<u8>, SshError> {
    public
        .to_bytes()
        .map_err(|e| SshError::AuthFailed(format!("the key is unusable: {e}")))
}

/// RSA uses the negotiated SHA-256 or SHA-512 digest, or legacy SHA-1 when
/// the server offers neither. Other key types take none. The outer `None`
/// means the session is gone.
async fn hash_for<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    wait: &Wait,
    public: &PublicKey,
) -> Result<Option<Option<HashAlg>>, SshError> {
    if !public.algorithm().is_rsa() {
        return Ok(Some(None));
    }
    match wait.on(login.handle.best_supported_rsa_hash()).await? {
        Ok(hash) => Ok(Some(hash.flatten())),
        Err(e) => session_gone(e).map(|()| None),
    }
}

/// Offer a prepared key and sign through the bounded crypto service.
async fn offer_private_key<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    wait: &Wait,
    key: sshauth::prepared_key::PreparedKey,
    offered: &mut std::collections::HashSet<Vec<u8>>,
) -> Result<Attempt, SshError> {
    if !offered.insert(canonical(key.public_key())?) {
        return Ok(Attempt::Duplicate);
    }
    let Some(hash) = hash_for(login, wait, key.public_key()).await? else {
        return Ok(Attempt::Gone);
    };
    // The built-in private-key method signs again inside russh's session
    // task after PK_OK, outside our cancellation checks. Keep that action in
    // the same guarded signer path as platform, encrypted-file and agent keys.
    let public = key.public_key().clone();
    let mut signer = PrivateSigner {
        key: Arc::new(key),
        #[cfg(test)]
        before_sign: None,
    };
    let sent = wait
        .on(login.handle.authenticate_publickey_with(
            login.username,
            public,
            hash,
            &mut GuardedSigner {
                signer: &mut signer,
                cancel: &wait.cancel,
            },
        ))
        .await?;
    signed(sent)
}

/// An encrypted key file: offered by its public half, the passphrase asked
/// only if the server answers that it would take the key.
async fn offer_locked_key<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    wait: &Wait,
    path: &std::path::Path,
    key: &russh::keys::PrivateKey,
    prompter: &dyn AuthPrompter,
    offered: &mut std::collections::HashSet<Vec<u8>>,
) -> Result<Vec<Attempt>, SshError> {
    let public = key.public_key();
    if !offered.insert(canonical(public)?) {
        return Ok(vec![Attempt::Duplicate]);
    }
    let Some(hash) = hash_for(login, wait, public).await? else {
        return Ok(vec![Attempt::Gone]);
    };
    let mut signer = keyfile::LazyKeySigner {
        path,
        key,
        prompter,
        clock: &login.clock,
        gave_up: None,
    };
    let sent = wait
        .on(login.handle.authenticate_publickey_with(
            login.username,
            public.clone(),
            hash,
            &mut GuardedSigner {
                signer: &mut signer,
                cancel: &wait.cancel,
            },
        ))
        .await?;
    let attempt = signed(sent)?;
    // Why no signature was made goes first, so it is on record even when
    // the session is gone.
    let mut attempts: Vec<Attempt> = signer.gave_up.map(Attempt::Skipped).into_iter().collect();
    attempts.push(attempt);
    Ok(attempts)
}

/// Every plain key of the agent at `socket`, one attempt each, until the
/// server no longer takes keys.
async fn offer_agent_keys<H: russh::client::Handler>(
    login: &mut Login<'_, H>,
    wait: &Wait,
    socket: &std::path::Path,
    offered: &mut std::collections::HashSet<Vec<u8>>,
) -> Result<Vec<Attempt>, SshError> {
    let no_agent = || {
        vec![Attempt::Skipped(format!(
            "agent: no agent at {}",
            socket.display()
        ))]
    };
    let mut agent = match wait.on(AgentClient::connect_uds(socket)).await {
        Ok(Ok(agent)) => agent,
        _ => return Ok(no_agent()),
    };
    let identities = match wait.on(agent.request_identities()).await {
        Ok(Ok(identities)) => identities,
        Ok(Err(e)) => return Ok(vec![Attempt::Skipped(format!("agent: {e}"))]),
        Err(_) => return Ok(no_agent()),
    };
    let mut attempts = Vec::new();
    for identity in identities {
        // Certificates are not offered.
        let AgentIdentity::PublicKey { key, .. } = identity else {
            continue;
        };
        if !offered.insert(canonical(&key)?) {
            attempts.push(Attempt::Duplicate);
            continue;
        }
        let Some(hash) = hash_for(login, wait, &key).await? else {
            attempts.push(Attempt::Gone);
            break;
        };
        let mut signer = AgentSigner {
            agent: &mut agent,
            failed: None,
        };
        let sent = wait
            .on(login.handle.authenticate_publickey_with(
                login.username,
                key,
                hash,
                &mut GuardedSigner {
                    signer: &mut signer,
                    cancel: &wait.cancel,
                },
            ))
            .await?;
        let attempt = signed(sent)?;
        if let Some(why) = signer.failed {
            attempts.push(Attempt::Skipped(format!("agent: {why}")));
        }
        let done = match &attempt {
            Attempt::Success | Attempt::Gone => true,
            Attempt::Refused { remaining } => !remaining.contains(&MethodKind::PublicKey),
            _ => false,
        };
        attempts.push(attempt);
        if done {
            break;
        }
    }
    if attempts.is_empty() {
        attempts.push(Attempt::Skipped(format!(
            "agent: no keys in the agent at {}",
            socket.display()
        )));
    }
    Ok(attempts)
}

/// A signed attempt's answer: `Dropped` is the session gone, a signer's own
/// failure ends the login with its reason.
fn signed(sent: Result<AuthResult, SignError>) -> Result<Attempt, SshError> {
    match sent {
        Ok(result) => Ok(outcome(result)),
        Err(SignError::Dropped) => Ok(Attempt::Gone),
        Err(SignError::Cancelled) => Err(SshError::Cancelled),
        Err(SignError::Busy) => Err(SshError::CryptoBusy),
        Err(SignError::Unavailable) => Err(SshError::Protocol(
            "private-key worker service is unavailable".into(),
        )),
        Err(SignError::Signer(reason)) => Err(SshError::AuthFailed(reason)),
    }
}

/// russh sends the signed userauth request after this future returns. A
/// synchronous signer/prompt may block the executor, so cancellation must be
/// checked again before releasing its signature to that dispatcher.
struct GuardedSigner<'a, S> {
    signer: &'a mut S,
    cancel: &'a knock::Cancel,
}
impl<S: russh::Signer<Error = SignError> + Send> russh::Signer for GuardedSigner<'_, S> {
    type Error = SignError;
    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = key.clone();
        async move {
            if self.cancel.is_cancelled() {
                return Err(SignError::Cancelled);
            }
            let result = self.signer.auth_sign(&key, hash_alg, to_sign).await;
            if self.cancel.is_cancelled() {
                return Err(SignError::Cancelled);
            }
            result
        }
    }
}

struct PrivateSigner {
    key: Arc<sshauth::prepared_key::PreparedKey>,
    #[cfg(test)]
    before_sign: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl russh::Signer for PrivateSigner {
    type Error = SignError;
    fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = self.key.clone();
        #[cfg(test)]
        let before = self.before_sign.clone();
        async move {
            crate::crypto_worker::run(move || {
                #[cfg(test)]
                if let Some(before) = before {
                    before();
                }
                keyfile::sign_with_hash_alg(&key, hash_alg, &to_sign)
                    .map(|blob| keyfile::append_signature(to_sign, &blob))
                    .map_err(SignError::Signer)
            })
            .await
            .map_err(SignError::from)?
        }
    }
}

/// Bridges a platform signer to russh. russh hands over the bytes to sign
/// and expects them back with `string(signature blob)` appended.
struct SignerBridge(Arc<dyn ExternalSigner>);

#[derive(Debug)]
pub(crate) enum SignError {
    Cancelled,
    Busy,
    Unavailable,
    /// russh could not hand the request or the signature to its session:
    /// the session is gone. Why -- the server's goodbye or a lost network --
    /// is read from the handler (see `ended`).
    Dropped,
    /// The platform signer failed or returned an unusable signature.
    Signer(String),
}

impl From<crate::crypto_worker::Error> for SignError {
    fn from(error: crate::crypto_worker::Error) -> Self {
        match error {
            crate::crypto_worker::Error::Busy => Self::Busy,
            crate::crypto_worker::Error::Unavailable => Self::Unavailable,
        }
    }
}
fn crypto_error(error: crate::crypto_worker::Error) -> SshError {
    match error {
        crate::crypto_worker::Error::Busy => SshError::CryptoBusy,
        crate::crypto_worker::Error::Unavailable => {
            SshError::Protocol("private-key worker service is unavailable".into())
        }
    }
}

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        SignError::Dropped
    }
}

impl russh::Signer for SignerBridge {
    type Error = SignError;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let signer = Arc::clone(&self.0);
        // russh supplies the public key from this authentication's offer, not
        // another read of the provider's potentially mutable public identity.
        let algorithm = match key.public_key().algorithm() {
            Algorithm::Rsa { .. } => Algorithm::Rsa { hash: hash_alg },
            other => other,
        };
        async move {
            // Synchronous on the connection's single-threaded runtime: while a
            // slow key store signs, nothing else runs, so a cancel is only
            // noticed after the signature returns.
            let blob = signer
                .sign_ssh_with_algorithm(&to_sign, algorithm.as_str())
                .map_err(SignError::Signer)?;
            let signature = sshauth::record::decode_signature(&blob)
                .map_err(|e| SignError::Signer(e.to_string()))?;
            if signature.algorithm() != algorithm {
                return Err(SignError::Signer(format!(
                    "external signature algorithm does not match requested {}",
                    algorithm.as_str()
                )));
            }
            Ok(keyfile::append_signature(to_sign, &blob))
        }
    }
}

/// The agent signs; if it cannot, the signature is sent empty (see
/// `keyfile::LazyKeySigner` for why an error is not returned) and the
/// reason kept.
struct AgentSigner<'a> {
    agent: &'a mut AgentClient<tokio::net::UnixStream>,
    failed: Option<String>,
}

impl russh::Signer for AgentSigner<'_> {
    type Error = SignError;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = key.clone();
        async move {
            match self
                .agent
                .sign_request(&key, hash_alg, to_sign.clone())
                .await
            {
                Ok(signed) => Ok(signed),
                Err(e) => {
                    self.failed = Some(e.to_string());
                    Ok(keyfile::append_signature(to_sign, &[]))
                }
            }
        }
    }
}

#[cfg(test)]
mod native_worker_tests {
    use super::*;
    use russh::Signer;
    use std::sync::{mpsc, Condvar, Mutex};

    #[test]
    fn native_rsa_cancel_drops_connection_runtime_while_owned_signing_is_held() {
        let pair = ssh_key::private::RsaKeypair::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            2048,
        )
        .unwrap();
        let key = sshauth::prepared_key::PreparedKey::from_key(
            ssh_key::PrivateKey::new(
                ssh_key::private::KeypairData::Rsa(pair),
                "generated cancellation fixture",
            )
            .unwrap(),
        )
        .unwrap();
        let identity = AgentIdentity::from(key.public_key().clone());
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let held = gate.clone();
        let mut signer = PrivateSigner {
            key: Arc::new(key),
            before_sign: Some(Arc::new(move || {
                entered_tx.send(()).unwrap();
                let (lock, changed) = &*held;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
            })),
        };
        let cancel = knock::Cancel::new();
        let worker_cancel = cancel.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let owner = std::thread::spawn(move || {
            let runtime = crate::runtime();
            let result = runtime.block_on(async {
                let mut guarded = GuardedSigner {
                    signer: &mut signer,
                    cancel: &worker_cancel,
                };
                crate::with_cancel(
                    guarded.auth_sign(&identity, Some(HashAlg::Sha512), vec![7; 32]),
                    &worker_cancel,
                )
                .await
            });
            drop(runtime);
            done_tx
                .send(matches!(result, Err(SshError::Cancelled)))
                .unwrap();
        });
        // Always release and join before asserting, including on the RED path.
        let entered = entered_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        cancel.cancel();
        let cancelled_before_release = done_rx.recv_timeout(Duration::from_secs(1));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        owner.join().unwrap();
        assert!(
            entered,
            "the actual signing owner must reach the held operation"
        );
        assert!(
            matches!(cancelled_before_release, Ok(true)),
            "cancellation and runtime drop must complete while native work remains held"
        );
    }
}

#[cfg(test)]
#[path = "auth_external_signer_tests.rs"]
mod external_signer_tests;
