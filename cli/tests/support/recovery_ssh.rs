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
        Arc, Condvar, Mutex, PoisonError,
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
    /// Commands whose worker has not yet reaped the child and joined its
    /// pipe readers.
    pub running: AtomicUsize,
    /// What `Server::drop` decided for each command still owned at teardown.
    pub teardown: Mutex<Vec<Teardown>>,
}
pub struct Finished {
    pub command: String,
    pub code: i32,
    pub stdout: Vec<u8>,
}
pub struct Teardown {
    pub group: i32,
    /// Whether teardown sent SIGKILL to the command's process group.
    pub signalled: bool,
}
/// Where `Server::start_shell` runs commands: `/bin/sh -c` with exactly
/// `env`, in `home`. Without it every command reports no installed qshd.
pub struct Shell {
    pub home: PathBuf,
    pub env: Vec<(String, String)>,
    /// Holds every command's worker at one point of its reaping.
    pub hold: Option<Arc<Hold>>,
}
/// A point in a worker's reaping, after its command has exited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// The child is a zombie and the worker still has custody of its pid.
    Exited,
    /// The worker has given up custody to reap; the child is not reaped yet.
    Released,
}
/// Stops each worker that reaches `stage` until `release`, or until
/// `HOLD_LIMIT` passes, so a failed test still lets its commands settle.
pub struct Hold {
    stage: Stage,
    state: Mutex<HoldState>,
    changed: Condvar,
}
#[derive(Default)]
struct HoldState {
    reached: bool,
    released: bool,
}
const HOLD_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);
impl Hold {
    pub fn at(stage: Stage) -> Arc<Self> {
        Arc::new(Self {
            stage,
            state: Mutex::default(),
            changed: Condvar::new(),
        })
    }
    /// Whether a worker reached the stage within 20 seconds.
    pub fn reached(&self) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, std::time::Duration::from_secs(20), |s| !s.reached)
            .unwrap();
        state.reached
    }
    pub fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
    fn pass(&self, stage: Stage) {
        if stage != self.stage {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.reached = true;
        self.changed.notify_all();
        let _ = self
            .changed
            .wait_timeout_while(state, HOLD_LIMIT, |s| !s.released);
    }
}
pub struct Server {
    pub port: u16,
    pub key: russh::keys::PublicKey,
    pub activity: Arc<Activity>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    running: Arc<Mutex<Vec<Running>>>,
}
/// One command `start_shell` started. Its worker owns the child, joins the
/// child's pipe readers, and waits for the exit without reaping, so the
/// zombie still holds the pid, which is also the group id. Then, under
/// `reaping`, it marks custody released, and only then reaps. Teardown
/// signals `group` only under `reaping` while it is unmarked; the id is
/// this command's for as long as that lock is held. `settled` disconnects
/// when the worker ends.
struct Running {
    group: rustix::process::Pid,
    reaping: Arc<Mutex<bool>>,
    settled: std::sync::mpsc::Receiver<()>,
    worker: std::thread::JoinHandle<()>,
}
/// How long teardown waits for killed commands to settle.
const SETTLE: std::time::Duration = std::time::Duration::from_secs(10);
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
        let running = Arc::new(Mutex::new(Vec::new()));
        let owned = running.clone();
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
                        let handler = Handler { activity: observed.clone(), channels: Vec::new(), shell: shell.clone(), stdin: HashMap::new(), running: owned.clone() };
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
            running,
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
        // No exec request can start a command once the runtime is gone.
        let _ = self.stop.take().unwrap().send(());
        let _ = self.thread.take().unwrap().join();
        let running = std::mem::take(&mut *self.running.lock().unwrap());
        // Only commands whose worker still has custody of the pid, by their
        // whole process group: a child the command left behind may hold the
        // pipes too. Holding `reaping` across the signal keeps the worker
        // from reaping, and so from releasing the id, until it is sent.
        for command in &running {
            let reaping = command
                .reaping
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let signalled = !*reaping;
            if signalled {
                let _ = rustix::process::kill_process_group(
                    command.group,
                    rustix::process::Signal::KILL,
                );
            }
            self.activity.teardown.lock().unwrap().push(Teardown {
                group: command.group.as_raw_pid(),
                signalled,
            });
        }
        let deadline = std::time::Instant::now() + SETTLE;
        let mut unsettled = Vec::new();
        for command in running {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match command.settled.recv_timeout(left) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    unsettled.push(command.group.as_raw_pid())
                }
                _ => {
                    let _ = command.worker.join();
                }
            }
        }
        // Timing out is not cleanup: say so, unless a test already failed.
        if !unsettled.is_empty() {
            let message = format!("fake SSH commands did not settle after SIGKILL: {unsettled:?}");
            if std::thread::panicking() {
                eprintln!("{message}");
            } else {
                panic!("{message}");
            }
        }
    }
}
struct Handler {
    activity: Arc<Activity>,
    channels: Vec<Channel<russh::server::Msg>>,
    shell: Option<Arc<Shell>>,
    stdin: HashMap<ChannelId, ChildStdin>,
    running: Arc<Mutex<Vec<Running>>>,
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
    // Reads to EOF even after the channel is gone, so the command never
    // blocks on a full pipe and its output is recorded whole.
    let mut buffer = [0; 16 * 1024];
    let mut read = Vec::new();
    while let Ok(n @ 1..) = from.read(&mut buffer) {
        read.extend_from_slice(&buffer[..n]);
        let _ = to.send(wrap(buffer[..n].to_vec()));
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
            use std::os::unix::process::CommandExt;
            let mut child = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&command)
                .env_clear()
                .envs(shell.env.iter().cloned())
                .current_dir(&shell.home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .expect("run the command in the private home");
            let group = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
            self.stdin.insert(channel, child.stdin.take().unwrap());
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let (stdout, stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
            let activity = self.activity.clone();
            let (settle, settled) = std::sync::mpsc::channel::<()>();
            let reaping = Arc::new(Mutex::new(false));
            let custody = reaping.clone();
            let hold = shell.hold.clone();
            activity.running.fetch_add(1, Ordering::SeqCst);
            let worker = std::thread::spawn(move || {
                let _settle = settle;
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
                // Wait without reaping: the zombie keeps the pid, and so the
                // group id, this command's while teardown may still signal.
                loop {
                    match rustix::process::waitid(
                        rustix::process::WaitId::Pid(group),
                        rustix::process::WaitIdOptions::EXITED
                            | rustix::process::WaitIdOptions::NOWAIT,
                    ) {
                        Err(rustix::io::Errno::INTR) => {}
                        exited => {
                            exited.expect("wait for the command to exit");
                            break;
                        }
                    }
                }
                let pass = |stage| hold.as_ref().map_or((), |hold| hold.pass(stage));
                pass(Stage::Exited);
                *custody.lock().unwrap_or_else(PoisonError::into_inner) = true;
                pass(Stage::Released);
                let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(255);
                activity.finished.lock().unwrap().push(Finished {
                    command,
                    code,
                    stdout,
                });
                activity.running.fetch_sub(1, Ordering::SeqCst);
                let _ = tx.send(Output::Exit(code as u32));
            });
            self.running.lock().unwrap().push(Running {
                group,
                reaping,
                settled,
                worker,
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
