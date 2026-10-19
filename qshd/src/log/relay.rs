//! Bounded, best-effort worker diagnostics. This is never an authentication seam.

use std::io::{self, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{
    recvmsg, send, socketpair, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType,
};

use super::Level;

const COMPONENT_BYTES: usize = 96;
const MESSAGE_BYTES: usize = 3072;
const PACKET_BYTES: usize = 2 + COMPONENT_BYTES + MESSAGE_BYTES;
pub(crate) const DRAIN_BUDGET: usize = 8;

pub(crate) struct Sender(OwnedFd);

pub(crate) struct Receiver {
    fd: OwnedFd,
    worker_pid: u32,
}

pub(crate) fn pair() -> io::Result<(Sender, Receiver)> {
    let (sender, receiver) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )?;
    Ok((
        Sender(sender),
        Receiver {
            fd: receiver,
            worker_pid: 0,
        },
    ))
}

impl Sender {
    /// One bounded syscall, no retry queue and no SIGPIPE when the helper is gone.
    pub(crate) fn report(&self, level: Level, component: &str, message: &str) -> bool {
        let component = super::bounded_text(component, COMPONENT_BYTES);
        let message = super::bounded_text(message, MESSAGE_BYTES);
        let mut packet = [0; PACKET_BYTES];
        packet[0] = level as u8;
        packet[1] = component.len() as u8;
        let end_component = 2 + component.len();
        packet[2..end_component].copy_from_slice(component.as_bytes());
        let end = end_component + message.len();
        packet[end_component..end].copy_from_slice(message.as_bytes());
        matches!(send(self.0.as_raw_fd(), &packet[..end], MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL), Ok(n) if n == end)
    }
}

impl Receiver {
    pub(crate) fn set_worker_pid(&mut self, pid: u32) {
        self.worker_pid = pid;
    }

    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// False removes the input from poll. A bad record consumes budget, just
    /// like a good one; a flooded diagnostic queue cannot monopolize the loop.
    pub(crate) fn drain(&self, mut emit: impl FnMut(u32, Level, &str, &str)) -> bool {
        for _ in 0..DRAIN_BUDGET {
            let mut packet = [0; PACKET_BYTES];
            // Linux permits at most 253 descriptors per SCM_RIGHTS message.
            // Own and close every installed descriptor even when rejecting it.
            let mut ancillary = nix::cmsg_space!([RawFd; 253]);
            let mut iov = [IoSliceMut::new(&mut packet)];
            let msg = match recvmsg::<()>(
                self.fd.as_raw_fd(),
                &mut iov,
                Some(&mut ancillary),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
            ) {
                Ok(msg) => msg,
                Err(nix::errno::Errno::EAGAIN) => return true,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return false,
            };
            let count = msg.bytes;
            let mut rejected = msg
                .flags
                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
            for control in msg.cmsgs() {
                rejected = true;
                if let ControlMessageOwned::ScmRights(fds) = control {
                    for fd in fds {
                        // SAFETY: recvmsg installed this fd; nothing else owns it.
                        drop(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
            }
            if count == 0 {
                return false;
            }
            if rejected || count < 2 {
                continue;
            }
            let component_len = packet[1] as usize;
            if component_len > COMPONENT_BYTES
                || 2 + component_len > count
                || count - 2 - component_len > MESSAGE_BYTES
            {
                continue;
            }
            let level = match packet[0] {
                1 => Level::Error,
                2 => Level::Warn,
                3 => Level::Info,
                4 => Level::Debug,
                5 => Level::Trace,
                _ => continue,
            };
            if let (Ok(component), Ok(message)) = (
                std::str::from_utf8(&packet[2..2 + component_len]),
                std::str::from_utf8(&packet[2 + component_len..count]),
            ) {
                emit(self.worker_pid, level, component, message);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{sendmsg, ControlMessage};
    use std::io::IoSlice;

    #[test]
    fn queue_saturation_and_closed_peer_do_not_block_sender() {
        let (sender, receiver) = pair().unwrap();
        let mut accepted = 0;
        while sender.report(Level::Info, "transport", &"x".repeat(MESSAGE_BYTES)) {
            accepted += 1;
            assert!(accepted < 10000, "the kernel queue must be bounded");
        }
        assert!(accepted > 0);
        let mut drained = 0;
        assert!(receiver.drain(|_, _, _, _| drained += 1));
        assert_eq!(drained, DRAIN_BUDGET.min(accepted));
        // A concurrent isolated logger test can briefly inherit CLOEXEC fds
        // between fork and exec. Shutdown proves peer loss independently of it.
        nix::sys::socket::shutdown(receiver.fd.as_raw_fd(), nix::sys::socket::Shutdown::Both)
            .unwrap();
        drop(receiver);
        assert!(!sender.report(Level::Error, "worker", "lost peer"));
    }

    #[test]
    fn invalid_packets_and_ancillary_descriptors_are_discarded_without_leaks() {
        let (sender, mut receiver) = pair().unwrap();
        receiver.set_worker_pid(42);
        for packet in [&[0, 0][..], &[3, 99][..], &[3, 0, 0xff][..]] {
            send(sender.0.as_raw_fd(), packet, MsgFlags::MSG_NOSIGNAL).unwrap();
        }
        send(
            sender.0.as_raw_fd(),
            &vec![0; PACKET_BYTES + 1],
            MsgFlags::MSG_NOSIGNAL,
        )
        .unwrap();
        let (read, write) = nix::unistd::pipe().unwrap();
        let raw = [write.as_raw_fd()];
        sendmsg::<()>(
            sender.0.as_raw_fd(),
            &[IoSlice::new(&[3, 0])],
            &[ControlMessage::ScmRights(&raw)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
        drop(write);
        assert!(sender.report(Level::Warn, "component", "message"));
        let mut seen = Vec::new();
        assert!(receiver.drain(|pid, level, component, message| {
            seen.push((pid, level, component.to_owned(), message.to_owned()));
        }));
        assert_eq!(
            seen,
            vec![(42, Level::Warn, "component".into(), "message".into())]
        );
        let mut fd_poll = [nix::poll::PollFd::new(
            read.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        assert_eq!(nix::poll::poll(&mut fd_poll, 0u8).unwrap(), 1);
        assert_eq!(
            nix::unistd::read(read.as_raw_fd(), &mut [0]).unwrap(),
            0,
            "received write fd was closed"
        );
        drop(sender);
        assert!(!receiver.drain(|_, _, _, _| panic!("no more records")));
    }

    #[test]
    fn oversized_utf8_fields_are_bounded_before_encoding() {
        let (sender, receiver) = pair().unwrap();
        assert!(sender.report(Level::Info, &"é".repeat(1000), &"🦀".repeat(10000)));
        let mut count = 0;
        assert!(receiver.drain(|_, _, component, message| {
            assert!(component.len() <= COMPONENT_BYTES);
            assert!(message.len() <= MESSAGE_BYTES);
            assert!(message.ends_with("[truncated]"));
            count += 1;
        }));
        assert_eq!(count, 1);
    }
}
