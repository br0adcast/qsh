//! Owned child private control; never drops a manager during cooperative drain.

use super::worker_control::{self, Received};
use super::worker_protocol::Fault;
use super::worker_stop::WorkerStop;
use std::{future::Future, os::unix::net::UnixStream};

pub(super) async fn drive<T>(
    socket: UnixStream,
    helper_pid: u32,
    stop: WorkerStop,
    manager: impl Future<Output = T>,
) -> T {
    drive_with(socket, helper_pid, stop, manager, worker_control::receive).await
}

async fn drive_with<T>(
    socket: UnixStream,
    helper_pid: u32,
    stop: WorkerStop,
    manager: impl Future<Output = T>,
    mut receive: impl FnMut(&UnixStream) -> Result<Received, Fault>,
) -> T {
    use super::worker_protocol::{Frame, StopReason};
    use tokio::io::unix::AsyncFd;
    let descriptor = match socket.set_nonblocking(true).and_then(|()| {
        // SAFETY: the moved UnixStream owns a valid, fixed fd. The
        // publisher's try_clone owns a different fd; closing that alias
        // cannot close or replace this one. Below we only borrow the
        // stream for receive, never replace it or close its raw fd.
        // Return/cancellation drops AsyncFd, which deregisters before
        // dropping the stream, including while readiness is pending.
        unsafe { AsyncFd::register(socket) }.map_err(std::io::Error::from)
    }) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            stop.fatal_hook(StopReason::Protocol)(&format!(
                "private worker control setup failed: {error}"
            ));
            return manager.await;
        }
    };
    tokio::pin!(manager);
    let mut receiving = true;
    loop {
        tokio::select! {
            // Always poll cleanup before another ready private packet. A
            // pending manager still permits the control receive to progress.
            biased;
            result = &mut manager => return result,
            packet = async {
                let mut ready = descriptor.readable().await
                    .map_err(|error| Fault::Os(error.raw_os_error().unwrap_or(nix::libc::EIO)))?;
                let packet = receive(descriptor.get_ref());
                if matches!(packet, Ok(Received::Empty)) { ready.clear_ready(); }
                packet
            }, if receiving => {
                match packet {
                    Ok(Received::Empty) => {},
                    Ok(Received::Yielded) => tokio::task::yield_now().await,
                    Ok(Received::Frame { sender, frame: Frame::Stop(reason) }) if sender == helper_pid => {
                        stop.request(reason);
                        // Stop is sticky and the parent has no further child
                        // records. Disable readiness, including persistent HUP.
                        receiving = false;
                    }
                    other => {
                        receiving = false;
                        stop.fatal_hook(StopReason::Protocol)(&format!("private worker control failed: {other:?}"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "worker_child_tests.rs"]
mod tests;
