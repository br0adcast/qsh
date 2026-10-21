//! Bounded Linux-private coordination receives, separate from child custody.

use super::worker_protocol::{decode, Fault, Frame};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

pub(super) fn pair() -> io::Result<(UnixStream, UnixStream)> {
    let pair = super::channel::pair()?;
    for socket in [&pair.0, &pair.1] {
        nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::PassCred, &true)?;
    }
    Ok(pair)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Received {
    Empty,
    Yielded,
    Eof,
    Frame { sender: u32, frame: Frame },
}

pub(super) struct Packet<const N: usize = 9> {
    pub(super) bytes: [u8; N],
    pub(super) len: usize,
    pub(super) sender: Option<i32>,
    pub(super) ancillary: bool,
    pub(super) truncated: bool,
}

pub(super) fn read_packet<const N: usize>(socket: &UnixStream) -> io::Result<Packet<N>> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    let mut bytes = [0; N];
    let mut iov = [io::IoSliceMut::new(&mut bytes)];
    let mut control = nix::cmsg_space!([RawFd; 8], nix::libc::ucred);
    // Both owned receiving ends enable SO_PASSCRED before any sender can run.
    // Credentials distinguish even a zero-byte packet from actual EOF. UID may
    // legitimately change during worker startup and is not an authority check.
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    let len = message.bytes;
    let truncated = message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let mut sender = None;
    let mut ancillary = false;
    // Close every descriptor the kernel installed, even on zero/truncated or
    // otherwise rejected packets. On Linux excess rights beyond the control
    // buffer are closed by the kernel; CTRUNC still rejects the entire packet.
    for item in message.cmsgs() {
        match item {
            ControlMessageOwned::ScmRights(rights) => {
                ancillary = true;
                for fd in rights {
                    // SAFETY: recvmsg installed this fd for this one receiver.
                    drop(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
            ControlMessageOwned::ScmCredentials(credentials) => {
                ancillary |= sender.replace(credentials.pid()).is_some();
            }
            _ => ancillary = true,
        }
    }
    Ok(Packet {
        bytes,
        len,
        sender,
        ancillary,
        truncated,
    })
}

fn receive_with(read: impl FnOnce() -> io::Result<Packet>) -> Result<Received, Fault> {
    let packet = match read() {
        Ok(packet) => packet,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            return Ok(Received::Yielded);
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Ok(Received::Empty);
        }
        Err(error) => return Err(Fault::Os(error.raw_os_error().unwrap_or(nix::libc::EIO))),
    };
    if packet.truncated {
        return Err(Fault::Truncated);
    }
    if packet.ancillary {
        return Err(Fault::Ancillary);
    }
    if packet.len == 0 && packet.sender.is_none() {
        return Ok(Received::Eof);
    }
    let sender = packet
        .sender
        .filter(|pid| *pid > 0)
        .ok_or(Fault::Protocol)? as u32;
    let frame = decode(&packet.bytes[..packet.len])?;
    Ok(Received::Frame { sender, frame })
}

pub(super) fn receive(socket: &UnixStream) -> Result<Received, Fault> {
    // One syscall per pass: sustained EINTR cannot starve other owners or reset
    // an absolute startup deadline. No child observation/reap occurs here.
    receive_with(|| read_packet::<9>(socket))
}

/// Exactly one fixed packet remains owned until the kernel accepts it.
pub(super) struct PendingFrame {
    bytes: [u8; 8],
    len: usize,
    sent: bool,
    failure: Option<Fault>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sent {
    Complete,
    Blocked,
    Yielded,
}
impl PendingFrame {
    pub(super) fn new(bytes: &[u8]) -> Result<Self, Fault> {
        decode(bytes)?;
        let mut fixed = [0; 8];
        fixed[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: fixed,
            len: bytes.len(),
            sent: false,
            failure: None,
        })
    }
    fn send_with(&mut self, send: impl FnOnce(&[u8]) -> io::Result<usize>) -> Result<Sent, Fault> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.sent {
            return Ok(Sent::Complete);
        }
        let failure = match send(&self.bytes[..self.len]) {
            Ok(len) if len == self.len => {
                self.sent = true;
                return Ok(Sent::Complete);
            }
            Ok(_) => Fault::Protocol,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(Sent::Yielded),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(Sent::Blocked),
            Err(error) => Fault::Os(error.raw_os_error().unwrap_or(nix::libc::EIO)),
        };
        self.failure = Some(failure);
        Err(failure)
    }
    pub(super) fn send(&mut self, socket: &UnixStream) -> Result<Sent, Fault> {
        self.send_with(|bytes| {
            nix::sys::socket::send(
                socket.as_raw_fd(),
                bytes,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT | nix::sys::socket::MsgFlags::MSG_NOSIGNAL,
            )
            .map_err(io::Error::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};

    #[test]
    fn worker40_private_packets_keep_stage_and_receipt_in_distinct_passes() {
        let (parent, child) = pair().unwrap();
        super::super::channel::send(&child, &[2, 0, 0, 1, 7], None).unwrap();
        super::super::channel::send(&child, &[4, 0, 0, 0, 15, 15, 0, 0], None).unwrap();
        drop(child);
        assert_eq!(
            receive(&parent),
            Ok(Received::Frame {
                sender: std::process::id(),
                frame: Frame::SessionEstablished(263),
            })
        );
        assert!(matches!(
            receive(&parent),
            Ok(Received::Frame {
                frame: Frame::Drained(_),
                ..
            })
        ));
        assert_eq!(receive(&parent), Ok(Received::Eof));
    }

    #[test]
    fn worker40_credentialed_zero_is_not_eof_and_leaves_following_stage_queued() {
        let (parent, child) = pair().unwrap();
        super::super::channel::send(&child, &[], None).unwrap();
        super::super::channel::send(&child, &[2, 0, 0, 1, 7], None).unwrap();
        drop(child);
        assert_eq!(receive(&parent), Err(Fault::Protocol));
        assert!(matches!(
            receive(&parent),
            Ok(Received::Frame {
                frame: Frame::SessionEstablished(263),
                ..
            })
        ));
        assert_eq!(receive(&parent), Ok(Received::Eof));
    }

    #[test]
    fn worker40_rejected_zero_packet_closes_installed_rights() {
        let (parent, child) = pair().unwrap();
        let (read, write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK)
                .unwrap();
        super::super::channel::send(&child, &[], Some(write.as_fd())).unwrap();
        drop(write);
        assert!(receive(&parent).is_err());
        let mut byte = [0];
        let closed = nix::unistd::read(read.as_raw_fd(), &mut byte);
        // Both endpoints stay alive: dropping a queued packet must not hide a
        // receiver which failed to consume/close its newly installed rights.
        drop(parent);
        drop(child);
        assert_eq!(
            closed,
            Ok(0),
            "all rejected received pipe writers must close"
        );
    }

    #[test]
    fn worker40_interrupted_receive_yields_then_preserves_next_real_stage() {
        let (parent, child) = pair().unwrap();
        super::super::channel::send(&child, &[2, 0, 0, 1, 7], None).unwrap();
        for _ in 0..32 {
            let mut calls = 0;
            assert_eq!(
                receive_with(|| {
                    calls += 1;
                    Err(io::ErrorKind::Interrupted.into())
                }),
                Ok(Received::Yielded)
            );
            assert_eq!(calls, 1);
        }
        assert!(matches!(
            receive(&parent),
            Ok(Received::Frame {
                frame: Frame::SessionEstablished(263),
                ..
            })
        ));
        assert_eq!(receive(&parent), Ok(Received::Empty));
    }

    #[test]
    fn worker40_interrupted_receive_never_proves_an_empty_queue() {
        let (parent, child) = pair().unwrap();
        super::super::channel::send(&child, &[2, 0, 0, 1, 7], None).unwrap();
        let interrupted = receive_with(|| Err(io::ErrorKind::Interrupted.into()));
        let empty = receive_with(|| Err(io::ErrorKind::WouldBlock.into()));
        // A caller which observed leader exit must not grant final-reap
        // permission from an interrupted read while this stage remains queued.
        assert_ne!(interrupted, empty, "interruption is not queue-empty proof");
        assert!(matches!(receive(&parent), Ok(Received::Frame { .. })));
    }

    #[test]
    fn worker40_truncated_payload_and_control_reject_without_fd_leak() {
        use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
        let (parent, child) = pair().unwrap();
        super::super::channel::send(&child, &[2; 32], None).unwrap();
        assert_eq!(receive(&parent), Err(Fault::Truncated));
        let (read, write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK)
                .unwrap();
        let rights = [write.as_raw_fd(); 32];
        sendmsg::<()>(
            child.as_raw_fd(),
            &[io::IoSlice::new(&[2, 0, 0, 1, 7])],
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(write);
        let result = receive(&parent);
        let closed = nix::unistd::read(read.as_raw_fd(), &mut [0]);
        drop(parent);
        drop(child);
        assert_eq!(result, Err(Fault::Truncated));
        assert_eq!(
            closed,
            Ok(0),
            "delivered and kernel-truncated rights all close"
        );
    }

    #[test]
    fn worker40_fixed_pending_send_keeps_one_packet_through_interrupt_and_backpressure() {
        let mut frame = PendingFrame::new(&[1, 0]).unwrap();
        let first = frame.send_with(|_| Err(io::ErrorKind::Interrupted.into()));
        let second = frame.send_with(|_| Err(io::ErrorKind::WouldBlock.into()));
        let mut observed = Vec::new();
        let third = frame.send_with(|bytes| {
            observed.extend_from_slice(bytes);
            Ok(bytes.len())
        });
        let fourth = frame.send_with(|_| panic!("a delivered packet must not be sent twice"));
        assert_eq!(first, Ok(Sent::Yielded));
        assert_eq!(second, Ok(Sent::Blocked));
        assert_eq!(third, Ok(Sent::Complete));
        assert_eq!(fourth, Ok(Sent::Complete));
        assert_eq!(observed, [1, 0]);
    }

    #[test]
    fn worker40_actual_private_send_delivers_one_packet_and_closed_peer_is_not_success() {
        let (parent, child) = pair().unwrap();
        let mut frame = PendingFrame::new(&[1, 0]).unwrap();
        let sent = frame.send(&parent);
        let received = receive(&child);
        drop(child);
        let failed = PendingFrame::new(&[1, 0]).unwrap().send(&parent);
        assert_eq!(sent, Ok(Sent::Complete));
        assert_eq!(
            received,
            Ok(Received::Frame {
                sender: std::process::id(),
                frame: Frame::Stop(super::super::worker_protocol::StopReason::Requested)
            })
        );
        assert!(matches!(
            failed,
            Err(Fault::Os(nix::libc::EPIPE | nix::libc::ECONNRESET))
        ));
    }

    #[test]
    fn worker40_short_private_send_never_claims_delivery() {
        let mut frame = PendingFrame::new(&[1, 0]).unwrap();
        assert_eq!(frame.send_with(|_| Ok(1)), Err(Fault::Protocol));
        assert_eq!(
            frame.send_with(|_| panic!("failed publication must stay failed")),
            Err(Fault::Protocol)
        );
    }
}
