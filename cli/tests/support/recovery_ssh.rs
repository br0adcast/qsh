//! Synthetic, loopback-only SSH server; counters expose the trust boundary.
#![allow(dead_code)]
use russh::{
    server::{Auth, Session},
    Channel, ChannelId,
};
use std::{
    collections::HashMap,
    io::{Read, Write},
    path::PathBuf,
    process::{ChildStdin, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
#[derive(Default)]
pub struct Activity {
    pub connections: AtomicUsize,
    pub auth: AtomicUsize,
    pub sign: AtomicUsize,
    pub exec: AtomicUsize,
    /// Every exec request's command, in arrival order, on any connection.
    pub commands: Mutex<Vec<String>>,
    /// Each command `Server::start_shell` ran, in completion order.
    pub finished: Mutex<Vec<Finished>>,
}
pub struct Finished {
    pub command: String,
    pub code: i32,
    pub stdout: Vec<u8>,
}
/// Where `Server::start_shell` runs commands: `/bin/sh -c` with exactly
/// `env`, in `home`. Without it every command reports no installed qshd.
pub struct Shell {
    pub home: PathBuf,
    pub env: Vec<(String, String)>,
}
pub struct Server {
    pub port: u16,
    pub key: russh::keys::PublicKey,
    pub activity: Arc<Activity>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    pub fn start() -> Self {
        Self::launch(None)
    }
    /// A server that runs each command for real, like sshd in `shell.home`.
    pub fn start_shell(shell: Shell) -> Self {
        Self::launch(Some(Arc::new(shell)))
    }
    fn launch(shell: Option<Arc<Shell>>) -> Self {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let key =
            russh::keys::decode_secret_key(&key.to_openssh(ssh_key::LineEnding::LF).unwrap(), None)
                .unwrap();
        let public = key.public_key().clone();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let activity = Arc::new(Activity::default());
        let observed = activity.clone();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let config = Arc::new(russh::server::Config { keys: vec![key], auth_rejection_time: std::time::Duration::ZERO, auth_rejection_time_initial: Some(std::time::Duration::ZERO), ..Default::default() });
                loop { tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        observed.connections.fetch_add(1, Ordering::SeqCst);
                        let config = config.clone();
                        let handler = Handler { activity: observed.clone(), channels: Vec::new(), shell: shell.clone(), stdin: HashMap::new() };
                        tokio::spawn(async move { if let Ok(session) = russh::server::run_stream(config, stream, handler).await { let _ = session.await; } });
                    }
                }}
            });
        });
        Self {
            port,
            key: public,
            activity,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    pub fn wire(&self) -> Vec<u8> {
        self.key.to_bytes().unwrap()
    }
    pub fn commands(&self) -> Vec<String> {
        self.activity.commands.lock().unwrap().clone()
    }
    pub fn untouched(&self) {
        assert_eq!(self.activity.auth.load(Ordering::SeqCst), 0);
        assert_eq!(self.activity.sign.load(Ordering::SeqCst), 0);
        assert_eq!(self.activity.exec.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = self.thread.take().unwrap().join();
    }
}
struct Handler {
    activity: Arc<Activity>,
    channels: Vec<Channel<russh::server::Msg>>,
    shell: Option<Arc<Shell>>,
    stdin: HashMap<ChannelId, ChildStdin>,
}
enum Output {
    Data(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(u32),
}
fn forward(
    mut from: impl Read,
    to: tokio::sync::mpsc::UnboundedSender<Output>,
    wrap: fn(Vec<u8>) -> Output,
) -> Vec<u8> {
    let mut buffer = [0; 16 * 1024];
    let mut read = Vec::new();
    while let Ok(n @ 1..) = from.read(&mut buffer) {
        read.extend_from_slice(&buffer[..n]);
        if to.send(wrap(buffer[..n].to_vec())).is_err() {
            break;
        }
    }
    read
}
impl russh::server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        self.activity.auth.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::reject())
    }
    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.activity.auth.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::Accept)
    }
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.activity.sign.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(stdin) = self.stdin.get_mut(&channel) {
            let _ = stdin.write_all(data);
        }
        Ok(())
    }
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stdin.remove(&channel);
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.activity.exec.fetch_add(1, Ordering::SeqCst);
        let command = String::from_utf8_lossy(command).into_owned();
        self.activity.commands.lock().unwrap().push(command.clone());
        session.channel_success(channel)?;
        if let Some(shell) = &self.shell {
            let mut child = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&command)
                .env_clear()
                .envs(shell.env.iter().cloned())
                .current_dir(&shell.home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("run the command in the private home");
            self.stdin.insert(channel, child.stdin.take().unwrap());
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let (stdout, stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
            let activity = self.activity.clone();
            std::thread::spawn(move || {
                let out = {
                    let tx = tx.clone();
                    std::thread::spawn(move || forward(stdout, tx, Output::Data))
                };
                let err = {
                    let tx = tx.clone();
                    std::thread::spawn(move || forward(stderr, tx, Output::Stderr))
                };
                let stdout = out.join().unwrap_or_default();
                let _ = err.join();
                let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(255);
                activity.finished.lock().unwrap().push(Finished {
                    command,
                    code,
                    stdout,
                });
                let _ = tx.send(Output::Exit(code as u32));
            });
            let handle = session.handle();
            tokio::spawn(async move {
                while let Some(output) = rx.recv().await {
                    let sent = match output {
                        Output::Data(bytes) => handle.data(channel, bytes).await.is_ok(),
                        Output::Stderr(bytes) => {
                            handle.extended_data(channel, 1, bytes).await.is_ok()
                        }
                        Output::Exit(code) => {
                            let _ = handle.exit_status_request(channel, code).await;
                            let _ = handle.eof(channel).await;
                            let _ = handle.close(channel).await;
                            false
                        }
                    };
                    if !sent {
                        break;
                    }
                }
            });
            return Ok(());
        }
        // No shell or daemon runs; report no installed qshd.
        session.exit_status_request(channel, 1)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
