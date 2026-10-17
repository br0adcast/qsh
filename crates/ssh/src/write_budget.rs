//! Keep logical payload credits through pinned russh 0.63.3's write pipeline.
//!
//! `data_bytes` only enqueues Bytes; the last owner is dropped after russh
//! serializes them (possibly after an earlier flush if its sending future
//! still owned a reference). Credits then wait for the next successful
//! transport flush. This bounds logical payload, not the temporary plaintext
//! and ciphertext copies required by compression/encryption.
//!
//! All serialization and transport polling run on the same current-thread
//! runtime. While a transport flush is pending, russh cannot serialize later
//! queued payload. Therefore its successful flush cannot release credits for
//! future data. Recheck this adapter when changing the pinned dependency.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, OwnedSemaphorePermit};

#[derive(Default)]
pub(crate) struct WriteCredits {
    serialized: Mutex<Vec<OwnedSemaphorePermit>>,
    until_close: Mutex<Vec<OwnedSemaphorePermit>>,
    pub(crate) changed: Notify,
}

impl WriteCredits {
    pub(crate) fn data(self: &Arc<Self>, bytes: Vec<u8>, permit: OwnedSemaphorePermit) -> Bytes {
        Bytes::from_owner(Payload {
            bytes,
            permit: Some(permit),
            credits: Arc::clone(self),
        })
    }

    pub(crate) fn needs_flush(&self) -> bool {
        !self.serialized.lock().unwrap().is_empty()
    }

    pub(crate) fn hold_until_close(&self, permits: Vec<OwnedSemaphorePermit>) {
        self.until_close.lock().unwrap().extend(permits);
    }
}

struct Payload {
    bytes: Vec<u8>,
    permit: Option<OwnedSemaphorePermit>,
    credits: Arc<WriteCredits>,
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.credits.serialized.lock().unwrap().push(permit);
            self.credits.changed.notify_one();
        }
    }
}

pub(crate) struct TrackedIo<S> {
    stream: S,
    credits: Arc<WriteCredits>,
}

impl<S> TrackedIo<S> {
    pub(crate) fn new(stream: S, credits: Arc<WriteCredits>) -> Self {
        Self { stream, credits }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.credits.serialized.lock().unwrap().clear();
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
