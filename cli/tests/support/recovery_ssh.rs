//! Synthetic, loopback-only SSH server; counters expose the trust boundary.
#![allow(dead_code)]
use russh::{
    server::{Auth, Session},
    Channel, ChannelId,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[derive(Default)]
pub struct Activity {
    pub connections: AtomicUsize,
    pub auth: AtomicUsize,
    pub sign: AtomicUsize,
    pub exec: AtomicUsize,
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
                        let handler = Handler { activity: observed.clone(), channels: Vec::new() };
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
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.activity.exec.fetch_add(1, Ordering::SeqCst);
        session.channel_success(channel)?;
        // No shell or daemon runs; report no installed qshd.
        session.exit_status_request(channel, 1)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
