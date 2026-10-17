//! The socket buffers a transport socket asks for (spec §4.12): a window's
//! burst must not overflow the kernel's queue, which drops datagrams without
//! a word and leaves the loss to a retransmit timeout.

/// What every transport socket asks for, each way (spec §3.2, §4.12): one
/// stream's window is about 590 KB in Linux's accounting (about 2.3 KB a
/// datagram), and several of them plus what arrives while the app is paused
/// (a collection, a Doze wake: 300 ms at 10 MB/s) is about 3 MB.
pub const SOCKET_BUFFER_REQUEST: usize = 4 * 1024 * 1024;

/// What a socket asked for and what the OS granted, each way, as the OS
/// reports it (`getsockopt`): Linux reports twice what it lets the data
/// use, and grants an unprivileged process at most `net.core.rmem_max` /
/// `wmem_max` (`SO_RCVBUFFORCE`, which would pass them, needs privileges a
/// personal daemon has not got, and is not used).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferReport {
    pub recv_requested: usize,
    pub recv_granted: usize,
    pub send_requested: usize,
    pub send_granted: usize,
}

impl BufferReport {
    /// The journal line (spec §4.12).
    pub fn line(&self) -> String {
        format!(
            "udp buffers: receive {} requested, {} granted; send {} requested, {} granted",
            self.recv_requested, self.recv_granted, self.send_requested, self.send_granted
        )
    }
}

/// Ask the OS for `SOCKET_BUFFER_REQUEST` each way on `socket` -- a std or a
/// tokio socket -- and read back what it granted. Never fails: a refused
/// request leaves the OS's default, which the report then shows; a size
/// that cannot be read back reads 0.
pub fn tune_udp_buffers<'s, S>(socket: &'s S) -> BufferReport
where
    socket2::SockRef<'s>: From<&'s S>,
{
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(SOCKET_BUFFER_REQUEST);
    let _ = sock.set_send_buffer_size(SOCKET_BUFFER_REQUEST);
    BufferReport {
        recv_requested: SOCKET_BUFFER_REQUEST,
        recv_granted: sock.recv_buffer_size().unwrap_or(0),
        send_requested: SOCKET_BUFFER_REQUEST,
        send_granted: sock.send_buffer_size().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §9.2 (L3): what was granted reads back and is above zero, and --
    /// on Linux, where the default is a known, smaller number -- above what
    /// an untouched socket gets. `> 0` alone cannot tell the fix from its
    /// absence: an untouched socket already carries the OS default, which is
    /// nonzero. The line names both ways.
    #[test]
    fn what_was_granted_reads_back() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let report = tune_udp_buffers(&socket);
        assert_eq!(report.recv_requested, SOCKET_BUFFER_REQUEST);
        assert_eq!(report.send_requested, SOCKET_BUFFER_REQUEST);
        assert!(
            report.recv_granted > 0 && report.send_granted > 0,
            "{report:?}"
        );
        #[cfg(target_os = "linux")]
        {
            let untouched = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let untouched = socket2::SockRef::from(&untouched);
            assert!(
                report.recv_granted > untouched.recv_buffer_size().unwrap_or(0),
                "recv not above an untouched socket's default: {report:?}"
            );
            assert!(
                report.send_granted > untouched.send_buffer_size().unwrap_or(0),
                "send not above an untouched socket's default: {report:?}"
            );
        }
        let line = report.line();
        assert!(
            line.starts_with("udp buffers: receive 4194304 requested, "),
            "{line}"
        );
        assert!(line.contains("; send 4194304 requested, "), "{line}");
    }

    /// The daemon's sockets are tokio's.
    #[cfg(feature = "tokio-driver")]
    #[tokio::test]
    async fn a_tokio_socket_is_sized_too() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        assert!(tune_udp_buffers(&socket).recv_granted > 0);
    }
}
