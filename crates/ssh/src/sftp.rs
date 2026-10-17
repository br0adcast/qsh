//! Bounded SFTP uploads on the connection's existing runtime.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use russh_sftp::client::{Config, RawSftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{oneshot, Notify, OwnedSemaphorePermit, Semaphore};

use crate::write_budget::WriteCredits;
use crate::SshError;

const CHUNK: usize = 32 * 1024;
const PACKET: u32 = 64 * 1024;
const OUTGOING_RESERVATION: u32 = 128 * 1024;
const MAX_NAME: usize = 4096;
const CANCEL_POLL: Duration = Duration::from_millis(10);
const CLEANUP: Duration = Duration::from_millis(250);

/// Bounds for one upload, including opening its subsystem and file.
#[derive(Clone, Copy, Debug)]
pub struct TransferLimits {
    pub total: Duration,
    pub idle: Duration,
    pub max_bytes: u64,
}

/// Progress counts only bytes acknowledged by the remote SFTP server.
pub trait UploadProgress: Send + Sync {
    fn uploaded(&self, bytes: u64, total: u64);
}

pub(crate) struct Upload {
    path: String,
    bytes: Arc<[u8]>,
    limits: TransferLimits,
    progress: Arc<dyn UploadProgress>,
    cancel: knock::Cancel,
    started: Instant,
    result: mpsc::Sender<Result<(), SshError>>,
    budget: OwnedSemaphorePermit,
    _active: OwnedSemaphorePermit,
}

type UploadResult = mpsc::Receiver<Result<(), SshError>>;

impl Upload {
    pub(crate) fn prepare(
        path: &str,
        bytes: Arc<[u8]>,
        limits: TransferLimits,
        progress: Arc<dyn UploadProgress>,
        cancel: &knock::Cancel,
        budget: &Arc<Semaphore>,
        active: &Arc<Semaphore>,
    ) -> Result<(Self, UploadResult), SshError> {
        if cancel.is_cancelled() {
            return Err(SshError::Cancelled);
        }
        if !path.starts_with('/') || path.contains('\0') || path.len() > MAX_NAME {
            return Err(SshError::Protocol(
                "SFTP requires a bounded absolute path".into(),
            ));
        }
        if bytes.len() as u64 > limits.max_bytes {
            return Err(SshError::ResourceLimit(
                "the SFTP upload exceeds its byte limit".into(),
            ));
        }
        let active = Arc::clone(active)
            .try_acquire_owned()
            .map_err(|_| SshError::ResourceLimit("another SFTP upload is already active".into()))?;
        // At most one request awaits a reply: WRITE <= 32,768 + 4,096
        // handle bytes + 25 framing bytes = 36,889; OPEN <= 4,117;
        // CLOSE <= 4,109; INIT = 9. Reserve 128 KiB for both the framed
        // packet and ChannelStream's outgoing copy, plus path/handle and
        // control requests. Thus the bound also covers both copies while
        // ChannelStream splits a packet across the SSH send window.
        let budget = Arc::clone(budget)
            .try_acquire_many_owned(OUTGOING_RESERVATION)
            .map_err(|_| {
                SshError::ResourceLimit("the SFTP outgoing byte budget is unavailable".into())
            })?;
        let (result, receiver) = mpsc::channel();
        Ok((
            Self {
                path: path.into(),
                bytes,
                limits,
                progress,
                cancel: cancel.clone(),
                started: Instant::now(),
                result,
                budget,
                _active: active,
            },
            receiver,
        ))
    }

    pub(crate) async fn run(
        self,
        handle: Arc<russh::client::Handle<crate::Handler>>,
        credits: Arc<WriteCredits>,
        stop: Arc<crate::session::Stop>,
    ) {
        let mut clock = Clock {
            start: self.started,
            last: self.started,
            limits: self.limits,
            cancel: &self.cancel,
        };
        // Keep the opening future alive across cancellation: pinned russh
        // cannot reclaim a late-confirmed channel after its receiver is lost.
        // The one upload slot also bounds pending-open ownership to one.
        let mut opening = Box::pin(handle.channel_open_session());
        let opened = clock.wait(async { Ok(opening.as_mut().await) }).await;
        let mut channel = match opened {
            Ok(Ok(channel)) => channel,
            Ok(Err(error)) => {
                drop(self._active);
                let _ = self.result.send(Err(protocol(error)));
                return;
            }
            Err(error) => {
                match tokio::time::timeout(CLEANUP, opening.as_mut()).await {
                    Ok(Ok(channel)) => {
                        if !matches!(
                            tokio::time::timeout(CLEANUP, channel.close()).await,
                            Ok(Ok(()))
                        ) {
                            stop.request("the cancelled SSH channel could not be closed".into());
                        }
                        if crate::session::confirm_requests(
                            &handle,
                            &credits,
                            vec![self.budget],
                            CLEANUP,
                        )
                        .await
                        .is_err()
                        {
                            stop.request("the late SSH channel close was not confirmed".into());
                        }
                    }
                    Ok(Err(_)) => {}
                    Err(_) => {
                        credits.hold_until_close(vec![self.budget]);
                        stop.request("the cancelled SSH channel opening did not finish".into());
                    }
                }
                drop(self._active);
                let _ = self.result.send(Err(error));
                return;
            }
        };
        let requested = clock
            .wait(async {
                channel
                    .request_subsystem(true, "sftp")
                    .await
                    .map_err(protocol)?;
                loop {
                    match channel.wait().await {
                        Some(russh::ChannelMsg::Success) => return Ok(()),
                        Some(russh::ChannelMsg::Failure)
                        | Some(russh::ChannelMsg::Close)
                        | None => {
                            return Err(SshError::Protocol(
                                "the SFTP subsystem was refused or closed".into(),
                            ));
                        }
                        _ => {}
                    }
                }
            })
            .await;
        if let Err(error) = requested {
            let _ = tokio::time::timeout(CLEANUP, channel.close()).await;
            let _ = crate::session::confirm_requests(&handle, &credits, vec![self.budget], CLEANUP)
                .await;
            drop(self._active);
            let _ = self.result.send(Err(error));
            return;
        }
        let abort = Arc::new(Abort::default());
        let writes = Arc::new(Writes::default());
        let (dropped, stopped) = oneshot::channel();
        let stream = Interruptible {
            stream: channel.into_stream(),
            abort: Arc::clone(&abort),
            writes: Arc::clone(&writes),
            dropped: Some(dropped),
        };
        let session = RawSftpSession::new_with_config(
            stream,
            Config {
                max_packet_len: PACKET,
                max_concurrent_writes: 1,
                max_concurrent_reads: 1,
                // The outer clock controls every wait, including subsecond test limits.
                request_timeout_secs: self.limits.total.as_secs().saturating_add(1),
                ..Config::default()
            },
        );
        let result = transfer(
            &session,
            &self.path,
            &self.bytes,
            self.progress.as_ref(),
            &mut clock,
            &mut Requests {
                handle: &handle,
                writes: &writes,
                target: 0,
            },
        )
        .await;
        let _ = session.close_session();
        abort.stop();
        drop(session);
        // russh-sftp owns separate read/write workers. Wake both, and wait for
        // the shared stream to drop before confirming its final outgoing FIFO.
        // ChannelStream copies Bytes internally; retain the reservation until
        // the FIFO barrier confirms the transport flush, rather than returning
        // credits when poll_write merely enqueues its copy.
        let stopped = async {
            stopped.await.map_err(|_| {
                SshError::Protocol("the SFTP stream stop notification was lost".into())
            })
        };
        // Normal completion obeys the caller's remaining network budgets.
        // Only failed/cancelled transfers use the short emergency deadline.
        let cleanup = if result.is_ok() {
            match clock.wait(stopped).await {
                Ok(()) => clock.wait(ping(&handle)).await,
                Err(error) => Err(error),
            }
        } else {
            match tokio::time::timeout(CLEANUP, stopped).await {
                Ok(Ok(())) => tokio::time::timeout(CLEANUP, ping(&handle))
                    .await
                    .unwrap_or_else(|_| {
                        Err(SshError::Protocol(
                            "the SFTP emergency write confirmation timed out".into(),
                        ))
                    }),
                _ => Err(SshError::Protocol(
                    "the SFTP stream workers did not stop".into(),
                )),
            }
        };
        if cleanup.is_err() {
            credits.hold_until_close(vec![self.budget]);
        } else {
            drop(self.budget);
        }
        drop(self._active);
        // A failed cleanup must never replace the original transfer error.
        let _ = self.result.send(result.and(cleanup));
    }
}

fn protocol(error: impl std::fmt::Display) -> SshError {
    SshError::Protocol(format!("SFTP: {error}"))
}

struct Clock<'a> {
    start: Instant,
    last: Instant,
    limits: TransferLimits,
    cancel: &'a knock::Cancel,
}

impl Clock<'_> {
    async fn wait<T>(
        &mut self,
        future: impl Future<Output = Result<T, SshError>>,
    ) -> Result<T, SshError> {
        tokio::pin!(future);
        loop {
            if self.cancel.is_cancelled() {
                return Err(SshError::Cancelled);
            }
            let remaining = self
                .limits
                .total
                .saturating_sub(self.start.elapsed())
                .min(self.limits.idle.saturating_sub(self.last.elapsed()));
            if remaining.is_zero() {
                return Err(SshError::Protocol("the SFTP transfer timed out".into()));
            }
            tokio::select! {
                biased;
                result = &mut future => {
                    let value = result?;
                    self.last = Instant::now();
                    return Ok(value);
                }
                _ = tokio::time::sleep(remaining.min(CANCEL_POLL)) => {}
            }
        }
    }
}

async fn transfer(
    session: &RawSftpSession,
    path: &str,
    bytes: &[u8],
    progress: &dyn UploadProgress,
    clock: &mut Clock<'_>,
    requests: &mut Requests<'_>,
) -> Result<(), SshError> {
    clock
        .wait(requests.wait(9, async { session.init().await.map_err(protocol) }))
        .await?;
    let file = clock
        .wait(requests.wait(path.len() as u64 + 21, async {
            session
                .open(
                    path,
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                    FileAttributes::default(),
                )
                .await
                .map_err(protocol)
        }))
        .await?;
    if file.handle.len() > MAX_NAME {
        return Err(SshError::ResourceLimit(
            "the SFTP file handle is too large".into(),
        ));
    }
    let mut uploaded = 0;
    let mut reported = Instant::now();
    for chunk in bytes.chunks(CHUNK) {
        clock
            .wait(
                requests.wait(chunk.len() as u64 + file.handle.len() as u64 + 25, async {
                    session
                        .write(&file.handle, uploaded, chunk.to_vec())
                        .await
                        .map_err(protocol)
                }),
            )
            .await?;
        uploaded += chunk.len() as u64;
        if reported.elapsed() >= Duration::from_millis(250) || uploaded == bytes.len() as u64 {
            progress.uploaded(uploaded, bytes.len() as u64);
            reported = Instant::now();
        }
    }
    clock
        .wait(requests.wait(file.handle.len() as u64 + 13, async {
            session.close(file.handle).await.map_err(protocol)
        }))
        .await?;
    if bytes.is_empty() {
        progress.uploaded(0, 0);
    }
    Ok(())
}

/// Count bytes actually consumed by ChannelStream, independently of peer
/// STATUS replies. RawSftpSession's own outgoing queue is unbounded.
#[derive(Default)]
struct Writes {
    consumed: AtomicU64,
    changed: Notify,
}

impl Writes {
    async fn wait(&self, target: u64) {
        loop {
            let changed = self.changed.notified();
            if self.consumed.load(Ordering::SeqCst) >= target {
                return;
            }
            changed.await;
        }
    }
}

struct Requests<'a> {
    handle: &'a russh::client::Handle<crate::Handler>,
    writes: &'a Writes,
    target: u64,
}

impl Requests<'_> {
    async fn wait<T>(
        &mut self,
        framed_bytes: u64,
        reply: impl Future<Output = Result<T, SshError>>,
    ) -> Result<T, SshError> {
        self.target += framed_bytes;
        let sent = async {
            self.writes.wait(self.target).await;
            // The peer can fabricate SFTP STATUS before consuming a request.
            // Wait for the whole local frame and its bounded FIFO ping too,
            // so neither the SFTP writer queue nor russh's FIFO can grow.
            // Ping and STATUS waits run together, without a second serial RTT.
            ping(self.handle).await
        };
        let (value, ()) = tokio::try_join!(reply, sent)?;
        Ok(value)
    }
}

async fn ping(handle: &russh::client::Handle<crate::Handler>) -> Result<(), SshError> {
    handle.send_ping().await.map_err(protocol)?;
    if handle.is_closed() {
        Err(SshError::Protocol(
            "the SSH connection closed before its SFTP request was written".into(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct Abort {
    stopped: AtomicBool,
    wakers: Mutex<[Option<Waker>; 2]>,
}

impl Abort {
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        for waker in self
            .wakers
            .lock()
            .unwrap()
            .iter_mut()
            .filter_map(Option::take)
        {
            waker.wake();
        }
    }
    fn check(&self, cx: &Context<'_>, direction: usize) -> io::Result<()> {
        self.wakers.lock().unwrap()[direction] = Some(cx.waker().clone());
        if self.stopped.load(Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SFTP worker stopped",
            ))
        } else {
            Ok(())
        }
    }
}

struct Interruptible<S> {
    stream: S,
    abort: Arc<Abort>,
    writes: Arc<Writes>,
    dropped: Option<oneshot::Sender<()>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Interruptible<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.abort.check(cx, 0)?;
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Interruptible<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.abort.check(cx, 1)?;
        match Pin::new(&mut self.stream).poll_write(cx, buf) {
            Poll::Ready(Ok(count)) => {
                self.writes
                    .consumed
                    .fetch_add(count as u64, Ordering::SeqCst);
                self.writes.changed.notify_one();
                Poll::Ready(Ok(count))
            }
            result => result,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.abort.check(cx, 1)?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.abort.check(cx, 1)?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
impl<S> Drop for Interruptible<S> {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}
