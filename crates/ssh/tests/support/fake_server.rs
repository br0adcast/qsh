//! An SSH server of our own, on russh, for the logins OpenSSH cannot be set
//! up for without root: passwords, keyboard-interactive rounds, and a
//! second factor after a key. Optional SFTP behaviors also expose refused
//! subsystems, blocked windows, missing acknowledgements, and oversized replies.
//!
//! One thread with a current-thread runtime serves every connection; it
//! listens on 127.0.0.1:0 through the listener it keeps, and ends when the
//! `FakeServer` is dropped.

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::server::{Auth, ChannelOpenHandle, Msg, Response, Session};
use russh::{Channel, MethodKind, MethodSet};

#[derive(Default, Clone)]
pub struct FakeAuth {
    /// Accept every user public key, for host-verification boundary tests.
    pub accept_any_key: bool,
    pub activity: Arc<ServerActivity>,
    /// Successive exec outputs, without running a shell or touching user state.
    pub exec_outputs: Vec<Vec<u8>>,
    pub open_gate: Option<Arc<tokio::sync::Notify>>,
    pub auth_none_gate: Option<Arc<tokio::sync::Notify>>,
    pub publickey_offer_gate: Option<Arc<tokio::sync::Notify>>,
    pub read_delay: Duration,
    pub sftp: Option<SftpBehavior>,
    pub sftp_channels: Arc<SftpChannels>,
    /// Accepted password, if password login is on.
    pub password: Option<String>,
    /// keyboard-interactive rounds: each round's prompts (text, echo) and expected answers.
    pub kbd_rounds: Vec<Vec<(String, bool, String)>>,
    /// Public keys (wire) accepted as a FIRST factor that then needs keyboard-interactive
    /// (partial success), like `AuthenticationMethods publickey,keyboard-interactive`.
    pub partial_keys: Vec<Vec<u8>>,
    /// Drop the TCP connection, without a word, at this point of the login:
    /// a network loss, not a refusal.
    pub hang_up: Option<HangUp>,
}

#[derive(Default)]
pub struct ServerActivity {
    pub connections: AtomicUsize,
    pub userauth: AtomicUsize,
    pub exec: AtomicUsize,
}

#[derive(Default)]
pub struct SftpChannels {
    pub opened: AtomicUsize,
    pub status_rounds: AtomicUsize,
    pub requested: AtomicUsize,
    pub closed: AtomicUsize,
    pub writes: AtomicUsize,
}

#[derive(Clone, Copy)]
pub enum SftpBehavior {
    EarlyStatus,
    Successful,
    Stalled,
    Denied,
    WriteStalled,
    OversizedReply,
}

/// Where a `FakeServer` drops the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HangUp {
    /// On the first login request of any method, `none` included.
    OnFirstAuth,
    /// On the first keyboard-interactive answer.
    OnKbdAnswer,
}

/// What a handler returns to end the connection without SSH_MSG_DISCONNECT:
/// russh's server then drops the socket.
fn hang_up() -> russh::Error {
    russh::Error::Disconnect
}

pub struct FakeServer {
    pub sftp_channels: Arc<SftpChannels>,
    pub port: u16,
    host_key: russh::keys::PublicKey,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeServer {
    pub fn start(auth: FakeAuth) -> FakeServer {
        let key = host_key();
        let host_key = key.public_key().clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().unwrap().port();
        let auth = Arc::new(auth);
        let sftp_channels = Arc::clone(&auth.sftp_channels);
        let config = Arc::new(russh::server::Config {
            methods: Login::new(Arc::clone(&auth)).methods(),
            // Rejections answer at once: the tests need no timing defence.
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            // A zero receive window stalls even the INIT write, so the tests
            // verify shutdown of a blocked SFTP writer as well as its reader.
            window_size: match auth.sftp {
                Some(SftpBehavior::Stalled) => 0,
                Some(SftpBehavior::EarlyStatus) => 256,
                _ => 2097152,
            },
            ..Default::default()
        });
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("fake-sshd".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).expect("listener");
                    loop {
                        tokio::select! {
                            _ = &mut stopped => return,
                            accepted = listener.accept() => {
                                let Ok((stream, _)) = accepted else { return };
                                auth.activity.connections.fetch_add(1, Ordering::SeqCst);
                                let handler = Login::new(Arc::clone(&auth));
                                let stream = DelayedRead { stream, delay: auth.read_delay, enabled: handler.authenticated.clone(), timer: None, ready: false };
                                let config = Arc::clone(&config);
                                tokio::spawn(async move {
                                    if let Ok(session) =
                                        russh::server::run_stream(config, stream, handler).await
                                    {
                                        let _ = session.await;
                                    }
                                });
                            }
                        }
                    }
                });
                // Dropping the runtime here drops every connection still served.
            })
            .expect("fake sshd thread");
        FakeServer {
            sftp_channels,
            port,
            host_key,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// The host key in SSH wire format, for `SshParams::known_host_keys`.
    pub fn host_public_key_wire(&self) -> Vec<u8> {
        self.host_key.to_bytes().expect("host key bytes")
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// An ed25519 host key made by ssh-keygen in a temp dir that goes with it.
fn host_key() -> russh::keys::PrivateKey {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("host_ed25519");
    let ok = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&path)
        .status()
        .expect("ssh-keygen")
        .success();
    assert!(ok, "ssh-keygen failed");
    let pem = std::fs::read_to_string(&path).unwrap();
    russh::keys::decode_secret_key(&pem, None).expect("host key")
}

/// One connection's login.
struct Login {
    authenticated: Arc<AtomicBool>,
    sftp_channel: Option<russh::ChannelId>,
    sftp_buffer: Vec<u8>,
    channels: Vec<Channel<Msg>>,
    auth: Arc<FakeAuth>,
    /// A key of `partial_keys` was accepted: keyboard-interactive is open.
    first_factor: bool,
    /// The keyboard-interactive round being answered.
    round: usize,
}

impl Login {
    fn new(auth: Arc<FakeAuth>) -> Self {
        Login {
            authenticated: Arc::new(AtomicBool::new(false)),
            sftp_channel: None,
            sftp_buffer: Vec::new(),
            channels: Vec::new(),
            auth,
            first_factor: false,
            round: 0,
        }
    }

    fn needs_first_factor(&self) -> bool {
        !self.auth.partial_keys.is_empty() && !self.first_factor
    }

    /// What the server lists as still possible.
    fn methods(&self) -> MethodSet {
        let mut kinds = Vec::new();
        if self.auth.accept_any_key {
            kinds.push(MethodKind::PublicKey);
        }
        if self.needs_first_factor() {
            // Only the key opens the way, as with `AuthenticationMethods`.
            kinds.push(MethodKind::PublicKey);
        } else {
            if self.auth.password.is_some() {
                kinds.push(MethodKind::Password);
            }
            if !self.auth.kbd_rounds.is_empty() {
                kinds.push(MethodKind::KeyboardInteractive);
            }
        }
        MethodSet::from(&kinds[..])
    }

    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(self.methods()),
            partial_success: false,
        }
    }

    fn hangs_up_on_first_auth(&self) -> bool {
        self.auth.hang_up == Some(HangUp::OnFirstAuth)
    }

    fn is_partial_key(&self, key: &russh::keys::PublicKey) -> bool {
        let wire = key.to_bytes().expect("key bytes");
        self.needs_first_factor() && self.auth.partial_keys.contains(&wire)
    }

    fn round(&self) -> Auth {
        let prompts: Vec<(Cow<'static, str>, bool)> = self.auth.kbd_rounds[self.round]
            .iter()
            .map(|(text, echo, _)| (Cow::Owned(text.clone()), *echo))
            .collect();
        Auth::Partial {
            name: Cow::Owned(format!("round {}", self.round + 1)),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(prompts),
        }
    }
}

impl russh::server::Handler for Login {
    type Error = russh::Error;

    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            self.sftp_channel = Some(channel);
            self.auth
                .sftp_channels
                .requested
                .fetch_add(1, Ordering::SeqCst);
        }
        if name == "sftp" && !matches!(self.auth.sftp, None | Some(SftpBehavior::Denied)) {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    fn adjust_window(&mut self, _channel: russh::ChannelId, current: u32) -> u32 {
        // After the first small adjustment, target=1 makes russh's
        // `remaining < target / 2` false even at zero. INIT and OPEN finish;
        // the first WRITE then stalls partway through its framed packet.
        if matches!(self.auth.sftp, Some(SftpBehavior::EarlyStatus)) {
            1
        } else {
            current
        }
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.sftp_channel != Some(channel)
            || !matches!(
                self.auth.sftp,
                Some(
                    SftpBehavior::WriteStalled
                        | SftpBehavior::OversizedReply
                        | SftpBehavior::Successful
                        | SftpBehavior::EarlyStatus
                )
            )
        {
            return Ok(());
        }
        self.sftp_buffer.extend_from_slice(data);
        while self.sftp_buffer.len() >= 4 {
            let length = u32::from_be_bytes(self.sftp_buffer[..4].try_into().unwrap()) as usize;
            if self.sftp_buffer.len() < length + 4 {
                break;
            }
            let packet: Vec<u8> = self.sftp_buffer.drain(..length + 4).collect();
            match packet[4] {
                // INIT: reply VERSION 3 with no extensions, or an oversized
                // frame length without any body to expose unbounded reads.
                1 => {
                    let reply = if matches!(self.auth.sftp, Some(SftpBehavior::OversizedReply)) {
                        vec![0, 1, 0, 1]
                    } else {
                        vec![0, 0, 0, 5, 2, 0, 0, 0, 3]
                    };
                    session.data(channel, reply)?;
                }
                // OPEN: a one-byte handle "h", preserving the request id.
                3 => {
                    let mut reply = vec![0, 0, 0, 10, 102];
                    reply.extend_from_slice(&packet[5..9]);
                    reply.extend_from_slice(&[0, 0, 0, 1, b'h']);
                    session.data(channel, reply)?;
                    if matches!(self.auth.sftp, Some(SftpBehavior::EarlyStatus)) {
                        let sender = session.handle();
                        let observed = Arc::clone(&self.auth.sftp_channels);
                        tokio::spawn(async move {
                            loop {
                                let mut replies = Vec::new();
                                for id in 2u32..=258 {
                                    replies.extend_from_slice(&status(id));
                                }
                                if sender.data(channel, replies).await.is_err() {
                                    break;
                                }
                                observed.status_rounds.fetch_add(1, Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        });
                    }
                }
                // WRITE: accept the bytes on SSH, but never acknowledge SFTP.
                6 => {
                    self.auth
                        .sftp_channels
                        .writes
                        .fetch_add(1, Ordering::SeqCst);
                    if matches!(self.auth.sftp, Some(SftpBehavior::Successful)) {
                        session.data(
                            channel,
                            status(u32::from_be_bytes(packet[5..9].try_into().unwrap())),
                        )?;
                    }
                }
                4 if matches!(self.auth.sftp, Some(SftpBehavior::Successful)) => {
                    session.data(
                        channel,
                        status(u32::from_be_bytes(packet[5..9].try_into().unwrap())),
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.auth
            .sftp_channels
            .closed
            .fetch_add(1, Ordering::SeqCst);
        if self.sftp_channel == Some(channel) {
            self.sftp_channel = None;
        }
        self.channels.retain(|held| held.id() != channel);
        Ok(())
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.auth.activity.userauth.fetch_add(1, Ordering::SeqCst);
        if self.hangs_up_on_first_auth() {
            return Err(hang_up());
        }
        if let Some(gate) = &self.auth.auth_none_gate {
            gate.notified().await;
        }
        Ok(self.reject())
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.auth.activity.userauth.fetch_add(1, Ordering::SeqCst);
        if self.hangs_up_on_first_auth() {
            return Err(hang_up());
        }
        if !self.needs_first_factor() && self.auth.password.as_deref() == Some(password) {
            self.authenticated.store(true, Ordering::SeqCst);
            return Ok(Auth::Accept);
        }
        Ok(self.reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth.activity.userauth.fetch_add(1, Ordering::SeqCst);
        if self.hangs_up_on_first_auth() {
            return Err(hang_up());
        }
        if let Some(gate) = &self.auth.publickey_offer_gate {
            gate.notified().await;
        }
        if self.auth.accept_any_key || self.is_partial_key(key) {
            return Ok(Auth::Accept);
        }
        Ok(self.reject())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth.activity.userauth.fetch_add(1, Ordering::SeqCst);
        if self.auth.accept_any_key {
            self.authenticated.store(true, Ordering::SeqCst);
            return Ok(Auth::Accept);
        }
        if !self.is_partial_key(key) {
            return Ok(self.reject());
        }
        self.first_factor = true;
        // russh 0.63.3 sends `partial_success` as false after a publickey
        // (it clears the flag it just set); the remaining methods still
        // name the second factor, which is what the client goes by.
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
            partial_success: true,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        self.auth.activity.userauth.fetch_add(1, Ordering::SeqCst);
        if self.hangs_up_on_first_auth() {
            return Err(hang_up());
        }
        if self.needs_first_factor() || self.auth.kbd_rounds.is_empty() {
            return Ok(self.reject());
        }
        let Some(response) = response else {
            self.round = 0;
            return Ok(self.round());
        };
        if self.auth.hang_up == Some(HangUp::OnKbdAnswer) {
            return Err(hang_up());
        }
        let answers: Vec<Vec<u8>> = response.map(|b| b.to_vec()).collect();
        let expected: Vec<Vec<u8>> = self.auth.kbd_rounds[self.round]
            .iter()
            .map(|(_, _, answer)| answer.as_bytes().to_vec())
            .collect();
        if answers != expected {
            self.round = 0;
            return Ok(self.reject());
        }
        self.round += 1;
        if self.round == self.auth.kbd_rounds.len() {
            return Ok(Auth::Accept);
        }
        Ok(self.round())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        _command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let index = self.auth.activity.exec.fetch_add(1, Ordering::SeqCst);
        if let Some(output) = self.auth.exec_outputs.get(index) {
            session.channel_success(channel)?;
            session.data(channel, output.clone())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.auth
            .sftp_channels
            .opened
            .fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = self.auth.open_gate.clone() {
            tokio::spawn(async move {
                gate.notified().await;
                reply.accept().await;
            });
        } else {
            reply.accept().await;
        }
        self.channels.push(channel);
        Ok(())
    }
}

fn status(id: u32) -> Vec<u8> {
    let mut reply = vec![0, 0, 0, 17, 101];
    reply.extend_from_slice(&id.to_be_bytes());
    reply.extend_from_slice(&[0; 12]);
    reply
}

struct DelayedRead {
    stream: tokio::net::TcpStream,
    delay: Duration,
    enabled: Arc<AtomicBool>,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    ready: bool,
}
impl tokio::io::AsyncRead for DelayedRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        use std::future::Future;
        if self.enabled.load(Ordering::SeqCst) && !self.delay.is_zero() && !self.ready {
            let delay = self.delay;
            let timer = self
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
            std::task::ready!(timer.as_mut().poll(cx));
            self.timer = None;
            self.ready = true;
        }
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if result.is_ready() {
            self.ready = false;
        }
        result
    }
}
impl tokio::io::AsyncWrite for DelayedRead {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
