#![forbid(unsafe_code)]

//! SSH for the core: one connection, logged in, carrying channels for the
//! session above it. Port knocking and the socket come from the core too,
//! so the address that was knocked is the address connected to.
//!
//! The login follows an `SshAuthPlan`, methods tried in order in the one
//! connection; any question for a person goes to its `AuthPrompter`, and
//! the core itself reads neither `SSH_AUTH_SOCK` nor `~/.ssh`.

mod auth;
mod crypto_worker;
mod host_key;
mod keyfile;
mod session;
mod sftp;
mod write_budget;

#[cfg(test)]
extern crate self as ssh;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use host_key::host_key_info;
pub use session::{connect, SshConnection, SshSubstrate};
pub use sftp::{TransferLimits, UploadProgress};
pub use zeroize::Zeroizing;

/// Setup progress before port knocking and before the TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshConnectStage {
    Knocking,
    Connecting,
}

/// Channel events from the connection's thread.
pub trait SshEvents: Send + Sync {
    fn on_connect_stage(&self, _stage: SshConnectStage) {}
    fn on_channel(&self, event: client::channel::SubstrateEvent);
    /// The connection is over. Called once. Every channel still open is
    /// over with it: some may have reported `Exit { code: -1 }` just before
    /// this, others nothing at all.
    fn on_closed(&self, reason: String);
}

/// Where and how to connect.
#[derive(Clone)]
pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// The remembered host keys for host:port in SSH wire format; empty =
    /// nothing is known. Their algorithms are offered first.
    pub known_host_keys: Vec<Vec<u8>>,
    /// Once the host name has resolved (within `knock::RESOLVE_BUDGET`, a
    /// ceiling of its own), one deadline this far ahead bounds the knock
    /// steps, their pauses and the TCP connect together; nothing restarts
    /// it. It also bounds the SSH greeting with key exchange, and each
    /// network wait of the login, separately; time spent asking a person
    /// is not counted.
    pub connect_timeout: Duration,
    /// Zero disables keepalive.
    pub keepalive_interval: Duration,
    pub compression: bool,
    pub tcp_nodelay: bool,
    /// Knock steps; empty = no knock.
    pub knock: Vec<knock::KnockStep>,
}

impl std::fmt::Debug for SshParams {
    // Knock payloads act as a shared secret: only their number is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("known_host_keys", &self.known_host_keys.len())
            .field("connect_timeout", &self.connect_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("compression", &self.compression)
            .field("tcp_nodelay", &self.tcp_nodelay)
            .field("knock_steps", &self.knock.len())
            .finish()
    }
}

/// One way to log in. The plan tries them in order, in one connection.
pub enum AuthMethod {
    /// A password known up front (the app's saved password).
    Password(Zeroizing<String>),
    /// PEM text of an unencrypted private key (OpenSSH or PKCS#8/PEM).
    PrivateKeyPem(Zeroizing<String>),
    /// A key that never leaves the platform's key store and only signs.
    Signer(Arc<dyn ExternalSigner>),
    /// Every plain key of the ssh-agent at this socket, in the agent's order
    /// (certificates are not offered).
    Agent(std::path::PathBuf),
    /// An OpenSSH private key file; its passphrase is asked lazily.
    KeyFile(std::path::PathBuf),
    /// A password asked from the prompter, only if the server takes passwords.
    AskPassword,
    /// keyboard-interactive, answered by the prompter.
    KeyboardInteractive,
}

impl std::fmt::Debug for AuthMethod {
    // Never prints a password, a passphrase or a key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password(_) => write!(f, "Password(..)"),
            AuthMethod::PrivateKeyPem(_) => write!(f, "PrivateKeyPem(..)"),
            AuthMethod::Signer(_) => write!(f, "Signer(..)"),
            AuthMethod::Agent(p) => write!(f, "Agent({})", p.display()),
            AuthMethod::KeyFile(p) => write!(f, "KeyFile({})", p.display()),
            AuthMethod::AskPassword => write!(f, "AskPassword"),
            AuthMethod::KeyboardInteractive => write!(f, "KeyboardInteractive"),
        }
    }
}

/// The methods to try, in order, and whoever may be asked for a secret.
pub struct SshAuthPlan {
    pub methods: Vec<AuthMethod>,
    pub prompter: Arc<dyn AuthPrompter>,
}

impl SshAuthPlan {
    /// One method and nobody to ask: the app's case.
    pub fn single(method: AuthMethod) -> Self {
        SshAuthPlan {
            methods: vec![method],
            prompter: Arc::new(NoPrompts),
        }
    }
}

/// One prompt of a keyboard-interactive round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub text: String,
    /// Whether the answer may be shown as it is typed.
    pub echo: bool,
}

/// Asks a person. `None` means "no answer": the method is skipped.
///
/// Called on the connection's own thread, and the call blocks it: while a
/// question is open nothing else of the connection runs, and a `cancel` of
/// the connect is not seen until the call returns. A prompter that must be
/// interruptible watches for that itself and returns `None`.
pub trait AuthPrompter: Send + Sync {
    fn passphrase(&self, key_path: &std::path::Path) -> Option<Zeroizing<String>>;
    fn password(&self, user: &str, host: &str) -> Option<Zeroizing<String>>;
    fn keyboard_interactive(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[Prompt],
    ) -> Option<Vec<Zeroizing<String>>>;
}

/// Never answers: the app, a background reconnect, `--no-password`.
pub struct NoPrompts;

impl AuthPrompter for NoPrompts {
    fn passphrase(&self, _: &std::path::Path) -> Option<Zeroizing<String>> {
        None
    }
    fn password(&self, _: &str, _: &str) -> Option<Zeroizing<String>> {
        None
    }
    fn keyboard_interactive(
        &self,
        _: &str,
        _: &str,
        _: &[Prompt],
    ) -> Option<Vec<Zeroizing<String>>> {
        None
    }
}

/// An external key that supplies SSH public keys and signatures.
pub trait ExternalSigner: Send + Sync {
    /// Public key in SSH wire format.
    fn public_key(&self) -> Result<Vec<u8>, String>;
    /// SSH-encoded signature over `data`, including its algorithm name.
    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Sign using the requested SSH signature algorithm, returning its SSH wire record.
    /// The argument identifies a signature algorithm, not merely a key format.
    /// For RSA, `rsa-sha2-256` and `rsa-sha2-512` select SHA-2; `ssh-rsa`
    /// selects legacy SHA-1 under the existing peer negotiation policy.
    /// Fixed-algorithm providers may retain
    /// this default; a returned record must still match the requested name.
    /// RSA providers supporting multiple hashes should override this method.
    fn sign_ssh_with_algorithm(&self, data: &[u8], _algorithm: &str) -> Result<Vec<u8>, String> {
        self.sign_ssh(data)
    }
}

/// A server's host key as shown to a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub key_type: String,
    pub key: Vec<u8>,
    /// "SHA256:" + unpadded base64 of SHA-256 over `key`.
    pub fingerprint: String,
}

/// Why a connection did not come up.
#[derive(Debug)]
pub enum SshError {
    Resolve(String),
    Cancelled,
    Connect(String),
    ResourceLimit(String),
    /// Local private-key workers are saturated; retry through the caller policy.
    CryptoBusy,
    /// The OS refused the TCP connect to `target`: its kind and own words.
    /// Kept as data so a caller can tell what it may mean on its system (a
    /// denied Local Network permission on macOS).
    Unreachable {
        target: std::net::SocketAddr,
        kind: std::io::ErrorKind,
        os_error: String,
    },
    UnknownHostKey(HostKeyInfo),
    HostKeyChanged(HostKeyInfo),
    AuthFailed(String),
    Protocol(String),
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Resolve(r)
            | SshError::Connect(r)
            | SshError::ResourceLimit(r)
            | SshError::AuthFailed(r)
            | SshError::Protocol(r) => write!(f, "{r}"),
            SshError::CryptoBusy => write!(f, "private-key workers are busy; retry the connection"),
            SshError::Cancelled => write!(f, "the connection was cancelled"),
            SshError::Unreachable {
                target, os_error, ..
            } => write!(f, "{target}: {os_error}"),
            SshError::UnknownHostKey(k) => write!(f, "unknown host key {}", k.fingerprint),
            SshError::HostKeyChanged(k) => write!(f, "the host key changed: {}", k.fingerprint),
        }
    }
}

impl std::error::Error for SshError {}

/// What the host-key check saw, for the error that follows a refusal.
#[derive(Default)]
pub(crate) struct HostKeySlot(Mutex<Option<Result<HostKeyInfo, SshError>>>);

/// How the russh session ended, as its handler was told; read when a login
/// step finds the session gone.
#[derive(Default)]
pub(crate) struct EndSlot(Mutex<Option<Ended>>);

impl EndSlot {
    pub(crate) fn take(&self) -> Option<Ended> {
        self.0.lock().unwrap().take()
    }
}

pub(crate) enum Ended {
    /// The server sent SSH_MSG_DISCONNECT with this description.
    ByServer(String),
    /// The server's refusal named no method russh knows.
    NoMethod,
    /// Anything else: an EOF, a reset, a broken packet.
    Lost,
}

pub(crate) struct Handler {
    known: Vec<Vec<u8>>,
    slot: Arc<HostKeySlot>,
    ended: Arc<EndSlot>,
}

impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            *self.slot.0.lock().unwrap() = Some(Err(SshError::Protocol(
                "the server offered a host certificate, which is not supported".into(),
            )));
            return Ok(false);
        };
        let wire = key.to_bytes().map_err(russh::Error::from)?;
        let info = host_key_info(&wire).map_err(|_| russh::Error::WrongServerSig)?;
        let (ok, verdict) = match host_key::judge(&wire, &self.known) {
            host_key::Verdict::Trusted => (true, Ok(info)),
            host_key::Verdict::Unknown => (false, Err(SshError::UnknownHostKey(info))),
            host_key::Verdict::Changed => (false, Err(SshError::HostKeyChanged(info))),
        };
        *self.slot.0.lock().unwrap() = Some(verdict);
        Ok(ok)
    }

    /// russh calls this before the session drops its reply channel, so a
    /// login step that finds the session gone can read why here. Errors are
    /// handed back, as russh's default does.
    async fn disconnected(
        &mut self,
        reason: russh::client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        use russh::client::DisconnectReason;
        let (ended, result) = match reason {
            DisconnectReason::ReceivedDisconnect(info) => (Ended::ByServer(info.message), Ok(())),
            DisconnectReason::Error(russh::Error::NoAuthMethod) => {
                (Ended::NoMethod, Err(russh::Error::NoAuthMethod))
            }
            DisconnectReason::Error(e) => (Ended::Lost, Err(e)),
        };
        *self.ended.0.lock().unwrap() = Some(ended);
        result
    }
}

/// A runtime for one connection's lifetime, on its own thread.
pub(crate) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
}

/// Knock, resolve, open the socket through `bind`, connect, check the host
/// key and log in. Returns the logged-in handle.
pub(crate) async fn establish(
    params: &SshParams,
    auth: SshAuthPlan,
    bind: Arc<dyn knock::SocketBind>,
    events: &dyn SshEvents,
    credits: Arc<write_budget::WriteCredits>,
    cancel: &knock::Cancel,
) -> Result<(russh::client::Handle<Handler>, HostKeyInfo), SshError> {
    let verified = establish_kex(params, bind, events, credits, cancel).await?;
    let mut handle = verified.handle;
    let mut login = auth::Login {
        handle: &mut handle,
        username: &params.username,
        host: &params.host,
        step_timeout: params.connect_timeout,
        clock: auth::PromptClock::default(),
        cancel: cancel.clone(),
        ended: verified.ended,
    };
    with_cancel(auth::authenticate(&mut login, auth), cancel).await??;
    Ok((handle, verified.host_key))
}

/// A checked key is published only after russh completes KEX, including
/// verification of the server's signature. The handler callback alone is
/// only an offer, not proof that the server owns that key.
struct VerifiedConnection {
    handle: russh::client::Handle<Handler>,
    host_key: HostKeyInfo,
    ended: Arc<EndSlot>,
}

async fn establish_kex(
    params: &SshParams,
    bind: Arc<dyn knock::SocketBind>,
    events: &dyn SshEvents,
    credits: Arc<write_budget::WriteCredits>,
    cancel: &knock::Cancel,
) -> Result<VerifiedConnection, SshError> {
    let (target, deadline) = open_target(params, bind.as_ref(), events, cancel)?;
    events.on_connect_stage(SshConnectStage::Connecting);
    let stream = tcp_connect(target, deadline, params, bind.as_ref(), cancel).await?;
    let stream = write_budget::TrackedIo::new(stream, credits);
    let mut config = russh::client::Config::default();
    if !params.keepalive_interval.is_zero() {
        config.keepalive_interval = Some(params.keepalive_interval);
        config.keepalive_max = 3;
    }
    config.preferred.compression =
        std::borrow::Cow::Owned(compression_preference(params.compression));
    config.preferred.key =
        std::borrow::Cow::Owned(host_key::host_key_preference(&params.known_host_keys));
    let slot = Arc::new(HostKeySlot::default());
    let ended = Arc::new(EndSlot::default());
    let handler = Handler {
        known: params.known_host_keys.clone(),
        slot: Arc::clone(&slot),
        ended: Arc::clone(&ended),
    };
    // russh's keepalive starts only after login, so a peer that accepts TCP
    // and then stays silent would hang here forever: the greeting with key
    // exchange is bounded by `connect_timeout`, and so is each network wait
    // of the login (see `auth::with_step_timeout`).
    let connecting = russh::client::connect_stream(Arc::new(config), stream, handler);
    let connected = match with_cancel(
        tokio::time::timeout(params.connect_timeout, connecting),
        cancel,
    )
    .await?
    {
        Ok(result) => result,
        Err(_) => {
            return Err(SshError::Connect(format!(
                "{target} did not complete the SSH handshake within {:?}",
                params.connect_timeout
            )))
        }
    };
    let handle = match connected {
        Ok(h) => h,
        Err(e) => {
            // A refused host key surfaces as a russh error; the slot says why.
            if let Some(Err(verdict)) = slot.0.lock().unwrap().take() {
                return Err(verdict);
            }
            return Err(SshError::Protocol(
                host_key::negotiation_error(&e).unwrap_or_else(|| e.to_string()),
            ));
        }
    };
    let host_key = slot.0.lock().unwrap().take().ok_or_else(|| {
        SshError::Protocol("the SSH handshake completed without a checked host key".into())
    })??;
    Ok(VerifiedConnection {
        handle,
        host_key,
        ended,
    })
}

/// Completes verified SSH key exchange and closes the connection without
/// user authentication or opening channels. Unknown and changed keys are
/// errors, just as for `connect`; a later connection must check its own key.
pub fn verify_host(
    params: SshParams,
    bind: Arc<dyn knock::SocketBind>,
    cancel: &knock::Cancel,
) -> Result<HostKeyInfo, SshError> {
    struct Silent;
    impl SshEvents for Silent {
        fn on_channel(&self, _: client::channel::SubstrateEvent) {}
        fn on_closed(&self, _: String) {}
    }
    // The runtime and handle are dropped together, closing the probe socket.
    runtime().block_on(async {
        let verified = establish_kex(
            &params,
            bind,
            &Silent,
            Arc::new(write_budget::WriteCredits::default()),
            cancel,
        )
        .await?;
        Ok(verified.host_key)
    })
}

/// The compression algorithms offered, most preferred first: OpenSSH's
/// delayed zlib (after login), plain zlib, then none.
fn compression_preference(on: bool) -> Vec<russh::compression::Name> {
    use russh::compression::{NONE, ZLIB, ZLIB_LEGACY};
    if on {
        vec![ZLIB_LEGACY, ZLIB, NONE]
    } else {
        vec![NONE]
    }
}

/// Knock if asked, and say which address to dial: the knocked one, or the
/// one the name resolves to -- the same single resolution either way -- and
/// the deadline the knock and the TCP connect share.
fn open_target(
    params: &SshParams,
    bind: &dyn knock::SocketBind,
    events: &dyn SshEvents,
    cancel: &knock::Cancel,
) -> Result<(SocketAddr, knock::Deadline), SshError> {
    open_target_with(
        params,
        events,
        cancel,
        knock::resolve,
        &mut knock::SystemClock,
        &mut knock::SocketKnockSender::new(BindRef(bind)),
    )
}

/// [`open_target`] with the resolver, the clock and the knock sender handed
/// in. Resolution keeps its own ceiling; the deadline is set when it is
/// over, before anything is knocked or dialled.
fn open_target_with(
    params: &SshParams,
    events: &dyn SshEvents,
    cancel: &knock::Cancel,
    resolve: impl FnOnce(&str, &knock::Cancel) -> Result<IpAddr, knock::KnockError>,
    clock: &mut impl knock::Clock,
    sender: &mut impl knock::BoundedKnockSender,
) -> Result<(SocketAddr, knock::Deadline), SshError> {
    let ip = resolve(&params.host, cancel).map_err(knock_error)?;
    // A cancel that came in during the lookup wins over refusing the budget.
    if cancel.is_cancelled() {
        return Err(SshError::Cancelled);
    }
    let target = SocketAddr::new(ip, params.port);
    let deadline =
        knock::Deadline::after(clock.now(), params.connect_timeout).ok_or_else(|| {
            SshError::Connect(if params.connect_timeout.is_zero() {
                format!("{target}: a zero connect timeout leaves no time to connect")
            } else {
                format!(
                    "{target}: the connect timeout {:?} is out of range",
                    params.connect_timeout
                )
            })
        })?;
    if !params.knock.is_empty() {
        events.on_connect_stage(SshConnectStage::Knocking);
        knock::run_within(ip, &params.knock, sender, clock, deadline, cancel)
            .map_err(|stopped| stopped_error(stopped, target, params))?;
    }
    Ok((target, deadline))
}

struct BindRef<'a>(&'a dyn knock::SocketBind);
impl knock::SocketBind for BindRef<'_> {
    fn bind(&self, fd: i32) -> bool {
        self.0.bind(fd)
    }
}

fn knock_error(e: knock::KnockError) -> SshError {
    match e {
        knock::KnockError::Resolve(r) => SshError::Resolve(r),
        knock::KnockError::Cancelled => SshError::Cancelled,
    }
}

fn stopped_error(stopped: knock::Stopped, target: SocketAddr, params: &SshParams) -> SshError {
    match stopped {
        knock::Stopped::Cancelled => SshError::Cancelled,
        knock::Stopped::Expired => connect_expired(target, params),
    }
}

/// The shared deadline was reached before the TCP connection was made.
/// Names the dialled target, never the knock's ports or data.
fn connect_expired(target: SocketAddr, params: &SshParams) -> SshError {
    SshError::Connect(if params.knock.is_empty() {
        format!(
            "{target} did not answer within {:?}",
            params.connect_timeout
        )
    } else {
        format!(
            "{target}: the knock and the connection did not finish within {:?}",
            params.connect_timeout
        )
    })
}

async fn tcp_connect(
    target: SocketAddr,
    deadline: knock::Deadline,
    params: &SshParams,
    bind: &dyn knock::SocketBind,
    cancel: &knock::Cancel,
) -> Result<tokio::net::TcpStream, SshError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(|e| SshError::Connect(format!("{target}: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // Best effort, like the transport's own sockets.
        let _ = bind.bind(socket.as_raw_fd());
    }
    #[cfg(not(unix))]
    let _ = bind;
    // The binder is a synchronous callback that nothing here can cut short:
    // look at the deadline and `cancel` again before dialling.
    deadline
        .check(Instant::now(), cancel)
        .map_err(|stopped| stopped_error(stopped, target, params))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| SshError::Connect(format!("{target}: {e}")))?;
    let std_stream: std::net::TcpStream = socket.into();
    let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
    let stream = match until_deadline(deadline, cancel, tokio_socket.connect(target)).await? {
        Some(Ok(s)) => s,
        Some(Err(e)) => {
            return Err(SshError::Unreachable {
                target,
                kind: e.kind(),
                os_error: e.to_string(),
            })
        }
        None => return Err(connect_expired(target, params)),
    };
    if params.tcp_nodelay {
        let _ = stream.set_nodelay(true);
    }
    Ok(stream)
}

/// Runs `fut` until it finishes or `deadline` is reached (`None`), whichever
/// comes first; a cancel wins over both. Every poll looks at `cancel` and
/// then the deadline, before it advances `fut` and again before it takes a
/// result: a future past the deadline is never polled (a first poll may be
/// what issues the dial), and a result that comes in late is not used.
/// `tokio::time::timeout_at` polls the future first and would do both.
async fn until_deadline<F: std::future::Future>(
    deadline: knock::Deadline,
    cancel: &knock::Cancel,
    fut: F,
) -> Result<Option<F::Output>, SshError> {
    use std::task::Poll;
    let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.instant()));
    tokio::pin!(fut, timer);
    // Tokio's clock: the same as `Instant::now()` unless a test pauses it.
    let stopped = || match deadline.check(tokio::time::Instant::now().into_std(), cancel) {
        Ok(_) => None,
        Err(knock::Stopped::Cancelled) => Some(Err(SshError::Cancelled)),
        Err(knock::Stopped::Expired) => Some(Ok(None)),
    };
    let bounded = std::future::poll_fn(|cx| {
        if let Some(stop) = stopped() {
            return Poll::Ready(stop);
        }
        let out = fut.as_mut().poll(cx);
        if let Some(stop) = stopped() {
            return Poll::Ready(stop);
        }
        match out {
            Poll::Ready(v) => Poll::Ready(Ok(Some(v))),
            // Wake at the deadline too; the timer firing is reaching it.
            Poll::Pending if std::future::Future::poll(timer.as_mut(), cx).is_ready() => {
                Poll::Ready(Ok(None))
            }
            Poll::Pending => Poll::Pending,
        }
    });
    with_cancel(bounded, cancel).await?
}

/// Runs `fut` until it finishes or `cancel` is set, checking every
/// `knock::SLICE`.
pub(crate) async fn with_cancel<F: std::future::Future>(
    fut: F,
    cancel: &knock::Cancel,
) -> Result<F::Output, SshError> {
    tokio::pin!(fut);
    // A ready I/O response may resume a multi-action future before the timer
    // branch runs. Check on every poll, including that wakeup, before advancing it.
    let guarded = std::future::poll_fn(|cx| {
        if cancel.is_cancelled() {
            return std::task::Poll::Ready(Err(SshError::Cancelled));
        }
        let out = fut.as_mut().poll(cx);
        if cancel.is_cancelled() {
            std::task::Poll::Ready(Err(SshError::Cancelled))
        } else {
            out.map(Ok)
        }
    });
    tokio::pin!(guarded);
    loop {
        tokio::select! {
            out = &mut guarded => return out,
            _ = tokio::time::sleep(knock::SLICE) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::compression::{NONE, ZLIB, ZLIB_LEGACY};

    #[test]
    fn cancel_wins_when_a_future_completes() {
        let cancel = knock::Cancel::new();
        let result = runtime().block_on(with_cancel(
            async {
                cancel.cancel();
                7
            },
            &cancel,
        ));
        assert!(matches!(result, Err(SshError::Cancelled)), "{result:?}");
    }

    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// Simulated time, shared by the resolver, the clock and the sender
    /// below, so a slow lookup or a long pause costs no real time.
    #[derive(Clone)]
    struct SimClock(Rc<Cell<Instant>>);

    impl knock::Clock for SimClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
        fn sleep(&mut self, d: Duration) {
            self.0.set(self.0.get() + d);
        }
    }

    /// Records when each knock went out and the deadline it was given.
    struct SimSender {
        clock: SimClock,
        sent: Rc<RefCell<Vec<(Instant, u16, knock::Deadline)>>>,
    }

    impl knock::BoundedKnockSender for SimSender {
        fn udp_within(
            &mut self,
            to: SocketAddr,
            _: &[u8],
            deadline: knock::Deadline,
            _: &knock::Cancel,
        ) -> Result<(), knock::Stopped> {
            self.sent
                .borrow_mut()
                .push((self.clock.0.get(), to.port(), deadline));
            Ok(())
        }
        fn tcp_within(
            &mut self,
            to: SocketAddr,
            payload: &[u8],
            deadline: knock::Deadline,
            cancel: &knock::Cancel,
        ) -> Result<(), knock::Stopped> {
            self.udp_within(to, payload, deadline, cancel)
        }
    }

    #[derive(Default)]
    struct Stages(Mutex<Vec<SshConnectStage>>);

    impl SshEvents for Stages {
        fn on_connect_stage(&self, stage: SshConnectStage) {
            self.0.lock().unwrap().push(stage);
        }
        fn on_channel(&self, _: client::channel::SubstrateEvent) {}
        fn on_closed(&self, _: String) {}
    }

    fn udp(port: u16, delay_after_ms: u32) -> knock::KnockStep {
        knock::KnockStep {
            protocol: knock::KnockProtocol::Udp,
            port,
            payload: b"secret".to_vec(),
            delay_after_ms,
        }
    }

    fn sim_params(connect_timeout: Duration, knock: Vec<knock::KnockStep>) -> SshParams {
        SshParams {
            host: "h.example".into(),
            port: 2222,
            username: "u".into(),
            known_host_keys: Vec::new(),
            connect_timeout,
            keepalive_interval: Duration::ZERO,
            compression: false,
            tcp_nodelay: true,
            knock,
        }
    }

    struct Acquired {
        result: Result<(SocketAddr, knock::Deadline), SshError>,
        start: Instant,
        sent: Vec<(Duration, u16, knock::Deadline)>,
        stages: Vec<SshConnectStage>,
        now: Instant,
    }

    /// Runs [`open_target_with`] on simulated time; the lookup takes
    /// `lookup` of it and then answers 192.0.2.7.
    fn acquire(params: &SshParams, lookup: Duration, cancel: &knock::Cancel) -> Acquired {
        let start = Instant::now();
        let clock = SimClock(Rc::new(Cell::new(start)));
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mut sender = SimSender {
            clock: clock.clone(),
            sent: Rc::clone(&sent),
        };
        let stages = Stages::default();
        let in_lookup = clock.clone();
        let result = open_target_with(
            params,
            &stages,
            cancel,
            |_, _| {
                in_lookup.0.set(in_lookup.0.get() + lookup);
                Ok("192.0.2.7".parse().unwrap())
            },
            &mut clock.clone(),
            &mut sender,
        );
        let sent = sent
            .borrow()
            .iter()
            .map(|(at, port, d)| (*at - start, *port, *d))
            .collect();
        Acquired {
            result,
            start,
            sent,
            stages: stages.0.into_inner().unwrap(),
            now: clock.0.get(),
        }
    }

    /// The lookup keeps its own ceiling: an 8 s lookup under a 10 s timeout
    /// still leaves 10 s, set when it ends, for the knock and the connect.
    #[test]
    fn the_deadline_starts_when_the_lookup_ends() {
        let p = sim_params(
            Duration::from_secs(10),
            vec![udp(7000, 9_000), udp(7001, 0)],
        );
        let a = acquire(&p, Duration::from_secs(8), &knock::Cancel::new());
        let (target, deadline) = a.result.expect("the knock fits");
        assert_eq!(target, "192.0.2.7:2222".parse().unwrap());
        assert_eq!(deadline.instant(), a.start + Duration::from_secs(18));
        let at: Vec<_> = a.sent.iter().map(|(at, port, _)| (*at, *port)).collect();
        assert_eq!(
            at,
            vec![
                (Duration::from_secs(8), 7000),
                (Duration::from_secs(17), 7001)
            ]
        );
        assert!(
            a.sent.iter().all(|(_, _, d)| *d == deadline),
            "one deadline"
        );
        assert_eq!(deadline.remaining(a.now), Some(Duration::from_secs(1)));
        assert_eq!(a.stages, vec![SshConnectStage::Knocking]);
    }

    /// Without a knock the connect keeps the whole timeout after the lookup.
    #[test]
    fn without_a_knock_the_connect_gets_the_whole_timeout() {
        let p = sim_params(Duration::from_secs(10), Vec::new());
        let a = acquire(&p, Duration::from_secs(8), &knock::Cancel::new());
        let (_, deadline) = a.result.unwrap();
        assert_eq!(deadline.remaining(a.now), Some(Duration::from_secs(10)));
        assert!(a.sent.is_empty() && a.stages.is_empty());
    }

    /// Pauses that do not fit end at the deadline as a connection error --
    /// not a resolver one -- naming neither a knocked port nor its data.
    #[test]
    fn a_knock_that_does_not_fit_is_a_connect_error() {
        let p = sim_params(
            Duration::from_secs(10),
            vec![udp(7000, 6_000), udp(7001, 5_000), udp(7002, 0)],
        );
        let a = acquire(&p, Duration::from_secs(8), &knock::Cancel::new());
        match a.result {
            Err(SshError::Connect(m)) => {
                assert!(m.contains("192.0.2.7:2222") && m.contains("knock"), "{m}");
                assert!(!m.contains("700") && !m.contains("secret"), "{m}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(a.sent.len(), 2, "the third step never goes");
        assert_eq!(a.now, a.start + Duration::from_secs(18));
    }

    #[test]
    fn a_zero_or_out_of_range_timeout_knocks_nothing() {
        for timeout in [Duration::ZERO, Duration::MAX] {
            let p = sim_params(timeout, vec![udp(7000, 0)]);
            let a = acquire(&p, Duration::from_secs(1), &knock::Cancel::new());
            assert!(
                matches!(a.result, Err(SshError::Connect(_))),
                "{:?}",
                a.result
            );
            assert!(a.sent.is_empty() && a.stages.is_empty());
        }
    }

    /// A cancel during a lookup that then answers wins over refusing a zero
    /// or out-of-range timeout.
    #[test]
    fn a_cancel_during_the_lookup_wins_over_a_refused_timeout() {
        for timeout in [Duration::ZERO, Duration::MAX] {
            let p = sim_params(timeout, vec![udp(7000, 0)]);
            let cancel = knock::Cancel::new();
            let sent = Rc::new(RefCell::new(Vec::new()));
            let stages = Stages::default();
            let r = open_target_with(
                &p,
                &stages,
                &cancel,
                |_, cancel| {
                    cancel.cancel();
                    Ok("192.0.2.7".parse().unwrap())
                },
                &mut knock::SystemClock,
                &mut SimSender {
                    clock: SimClock(Rc::new(Cell::new(Instant::now()))),
                    sent: Rc::clone(&sent),
                },
            );
            assert!(matches!(r, Err(SshError::Cancelled)), "{timeout:?}: {r:?}");
            assert!(sent.borrow().is_empty() && stages.0.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn a_lookup_failure_stays_a_resolve_error() {
        let p = sim_params(Duration::from_secs(10), vec![udp(7000, 0)]);
        let r = open_target_with(
            &p,
            &Stages::default(),
            &knock::Cancel::new(),
            |_, _| Err(knock::KnockError::Resolve("h.example: no such host".into())),
            &mut knock::SystemClock,
            &mut SimSender {
                clock: SimClock(Rc::new(Cell::new(Instant::now()))),
                sent: Rc::default(),
            },
        );
        assert!(matches!(r, Err(SshError::Resolve(_))), "{r:?}");
    }

    #[test]
    fn a_cancel_before_the_knock_sends_nothing() {
        let cancel = knock::Cancel::new();
        cancel.cancel();
        let p = sim_params(Duration::from_secs(10), vec![udp(7000, 0)]);
        let a = acquire(&p, Duration::ZERO, &cancel);
        assert!(
            matches!(a.result, Err(SshError::Cancelled)),
            "{:?}",
            a.result
        );
        assert!(a.sent.is_empty());
    }

    fn paused() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
    }

    /// The TCP connect gets only what the knock left of the deadline.
    #[test]
    fn the_connect_gets_only_the_rest_of_the_deadline() {
        paused().block_on(async {
            let start = tokio::time::Instant::now();
            let deadline =
                knock::Deadline::after(start.into_std(), Duration::from_secs(10)).unwrap();
            // The knock's share.
            tokio::time::advance(Duration::from_secs(7)).await;
            let dial = tokio::time::Instant::now();
            let r = until_deadline(
                deadline,
                &knock::Cancel::new(),
                std::future::pending::<()>(),
            )
            .await;
            assert!(matches!(r, Ok(None)), "{r:?}");
            let took = dial.elapsed();
            assert!(
                took >= Duration::from_secs(3)
                    && took <= Duration::from_secs(3) + Duration::from_millis(1),
                "took {took:?}"
            );
        });
    }

    #[test]
    fn a_cancel_wins_over_a_connect_that_is_ready() {
        paused().block_on(async {
            let deadline = knock::Deadline::after(Instant::now(), Duration::from_secs(10)).unwrap();
            let cancel = knock::Cancel::new();
            let r = until_deadline(deadline, &cancel, async {
                cancel.cancel();
            })
            .await;
            assert!(matches!(r, Err(SshError::Cancelled)), "{r:?}");
            let r = until_deadline(deadline, &knock::Cancel::new(), async { 7 }).await;
            assert!(matches!(r, Ok(Some(7))), "{r:?}");
        });
    }

    /// A connect that counts its polls; ready once tokio's clock reaches
    /// `ready_at`, after `takes` of real time spent in the poll.
    struct Counted {
        polls: Rc<Cell<u32>>,
        ready_at: tokio::time::Instant,
        takes: Duration,
    }

    impl std::future::Future for Counted {
        type Output = u32;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<u32> {
            self.polls.set(self.polls.get() + 1);
            std::thread::sleep(self.takes);
            if tokio::time::Instant::now() >= self.ready_at {
                std::task::Poll::Ready(7)
            } else {
                std::task::Poll::Pending
            }
        }
    }

    /// At its deadline and past it, a connect is never polled, ready or not:
    /// its first poll may be the dial.
    #[test]
    fn a_connect_is_not_polled_at_or_past_the_deadline() {
        for past in [Duration::ZERO, Duration::from_secs(1)] {
            for ready in [true, false] {
                paused().block_on(async {
                    let start = tokio::time::Instant::now();
                    let deadline =
                        knock::Deadline::after(start.into_std(), Duration::from_secs(3)).unwrap();
                    tokio::time::advance(Duration::from_secs(3) + past).await;
                    let polls = Rc::new(Cell::new(0));
                    let r = until_deadline(
                        deadline,
                        &knock::Cancel::new(),
                        Counted {
                            polls: Rc::clone(&polls),
                            ready_at: if ready {
                                start
                            } else {
                                start + Duration::from_secs(99)
                            },
                            takes: Duration::ZERO,
                        },
                    )
                    .await;
                    assert!(matches!(r, Ok(None)), "{past:?} {ready}: {r:?}");
                    assert_eq!(polls.get(), 0, "{past:?} {ready}");
                });
            }
        }
    }

    /// A cancel is looked at first: a cancelled connect is not polled, and
    /// the cancel wins over an expiry on the same look.
    #[test]
    fn a_cancelled_connect_is_not_polled() {
        for past in [None, Some(Duration::from_secs(3))] {
            paused().block_on(async {
                let start = tokio::time::Instant::now();
                let deadline =
                    knock::Deadline::after(start.into_std(), Duration::from_secs(3)).unwrap();
                if let Some(past) = past {
                    tokio::time::advance(past).await;
                }
                let cancel = knock::Cancel::new();
                cancel.cancel();
                let polls = Rc::new(Cell::new(0));
                let r = until_deadline(
                    deadline,
                    &cancel,
                    Counted {
                        polls: Rc::clone(&polls),
                        ready_at: start,
                        takes: Duration::ZERO,
                    },
                )
                .await;
                assert!(matches!(r, Err(SshError::Cancelled)), "{past:?}: {r:?}");
                assert_eq!(polls.get(), 0, "{past:?}");
            });
        }
    }

    /// A connect that becomes ready just as the deadline is reached is not
    /// used: the deadline is looked at before the future is polled again.
    #[test]
    fn a_connect_ready_at_the_deadline_is_too_late() {
        paused().block_on(async {
            let start = tokio::time::Instant::now();
            let deadline =
                knock::Deadline::after(start.into_std(), Duration::from_secs(3)).unwrap();
            let polls = Rc::new(Cell::new(0));
            let r = until_deadline(
                deadline,
                &knock::Cancel::new(),
                Counted {
                    polls: Rc::clone(&polls),
                    ready_at: start + Duration::from_secs(3),
                    takes: Duration::ZERO,
                },
            )
            .await;
            assert!(matches!(r, Ok(None)), "{r:?}");
            assert!(polls.get() >= 1, "polled while time was left");
            assert_eq!(start.elapsed(), Duration::from_secs(3));
        });
    }

    /// A result that a poll returns only after the deadline passed during
    /// that poll is not used either.
    #[test]
    fn a_connect_result_that_comes_back_late_is_not_used() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let start = tokio::time::Instant::now();
            let deadline =
                knock::Deadline::after(start.into_std(), Duration::from_millis(100)).unwrap();
            let polls = Rc::new(Cell::new(0));
            let r = until_deadline(
                deadline,
                &knock::Cancel::new(),
                Counted {
                    polls: Rc::clone(&polls),
                    ready_at: start,
                    takes: Duration::from_millis(150),
                },
            )
            .await;
            assert!(matches!(r, Ok(None)), "{r:?}");
            assert_eq!(polls.get(), 1);
        });
    }

    #[test]
    fn compression_on_prefers_openssh_zlib_then_zlib_then_none() {
        assert_eq!(compression_preference(true), vec![ZLIB_LEGACY, ZLIB, NONE]);
    }

    #[test]
    fn compression_off_offers_only_none() {
        assert_eq!(compression_preference(false), vec![NONE]);
    }
}
