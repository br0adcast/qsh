//! One message, and optionally one file descriptor, across the `socketpair`
//! the two halves share.
//!
//! `SOCK_SEQPACKET` rather than `SOCK_STREAM`: the kernel keeps message
//! boundaries, so neither side has to frame anything, and a short read
//! cannot silently split a message in half.
//!
//! The pair is created before the fork, so it has no name in the file
//! system, no permissions to get wrong, and no way for a third process to
//! connect to it.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
    SockFlag, SockType,
};

use super::protocol::MAX_MESSAGE_LEN;

/// Create the pair. Both ends are close-on-exec: a child the helper spawns
/// must never inherit the seam it is not a party to.
pub fn pair() -> io::Result<(UnixStream, UnixStream)> {
    let (a, b) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(io::Error::from)?;
    Ok((UnixStream::from(a), UnixStream::from(b)))
}

/// Send one message, with `fd` alongside it when there is one.
///
/// Retries on `EINTR` itself: a signal landing mid-syscall is not a failed
/// send, and a caller (in particular the helper's loop, which already
/// retries its own `poll` on `EINTR`) must not have to remember to retry
/// this too.
pub fn send(sock: &UnixStream, bytes: &[u8], fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
    let iov = [io::IoSlice::new(bytes)];
    let fds: [RawFd; 1];
    let cmsgs: &[ControlMessage] = match fd {
        Some(fd) => {
            fds = [fd.as_raw_fd()];
            &[ControlMessage::ScmRights(&fds)]
        }
        None => &[],
    };
    loop {
        match sendmsg::<()>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None) {
            Ok(_) => return Ok(()),
            Err(nix::Error::EINTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// Receive one message. `Ok(None)` means the peer closed its end -- not an
/// error, but the fact each half watches for to know the other is gone.
///
/// Retries on `EINTR` itself, for the same reason [`send`] does: a signal
/// landing between `poll` waking the helper's loop and this call running
/// must not be mistaken for the peer having failed.
pub fn recv(sock: &UnixStream) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
    receive_with(|| receive_packet(sock), true)
}

/// One receive attempt for a live owner pump. EINTR yields without closing the
/// seam or consuming its queued record; the next pass retries after other owners.
pub(super) fn recv_once(sock: &UnixStream) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
    receive_with(|| receive_packet(sock), false)
}

fn receive_with<T>(
    mut read: impl FnMut() -> io::Result<T>,
    retry_interrupts: bool,
) -> io::Result<T> {
    loop {
        match read() {
            Err(error) if retry_interrupts && error.kind() == io::ErrorKind::Interrupted => {
                continue
            }
            result => return result,
        }
    }
}

fn receive_packet(sock: &UnixStream) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
    let mut buf = vec![0u8; MAX_MESSAGE_LEN];
    // Credential-enabled private monitor peers still carry one terminal fd.
    #[cfg(target_os = "linux")]
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1], nix::libc::ucred);
    #[cfg(not(target_os = "linux"))]
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    // `iov` must outlive `msg` (nix ties `RecvMsg`'s lifetime to it), so it
    // stays in this scope rather than a nested block.
    let mut iov = [io::IoSliceMut::new(&mut buf)];
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(io::Error::from)?;

    let bytes = msg.bytes;
    let truncated = msg
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let mut received_fd = None;
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            for raw in fds {
                // Every installed descriptor is owned even for a zero record;
                // returning EOF below drops it rather than leaking it.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                if received_fd.is_none() {
                    received_fd = Some(owned);
                }
            }
        }
    }
    // `msg` (and so `iov`'s borrow of `buf`) is not used past this point,
    // which is why `buf` can be mutated again below.

    if truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated helper message",
        ));
    }
    if bytes == 0 {
        return Ok(None);
    }
    buf.truncate(bytes);
    Ok(Some((buf, received_fd)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent40_interrupted_receive_yields_without_consuming_the_next_record() {
        let mut attempts = 0;
        let result = receive_with(
            || {
                attempts += 1;
                if attempts <= 3 {
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    Ok(7)
                }
            },
            false,
        );
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
        assert_eq!(attempts, 1);
        let mut attempts = 0;
        let legacy = receive_with(
            || {
                attempts += 1;
                if attempts <= 3 {
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    Ok(7)
                }
            },
            true,
        );
        assert_eq!(legacy.unwrap(), 7);
        assert_eq!(attempts, 4);
    }

    #[test]
    fn a_message_crosses_the_pair() {
        let (a, b) = pair().expect("socketpair");
        send(&a, b"hello", None).expect("send");
        let (bytes, fd) = recv(&b).expect("recv").expect("not closed");
        assert_eq!(bytes, b"hello");
        assert!(fd.is_none());
    }

    /// The whole point of the pair: a descriptor opened on one side becomes a
    /// usable descriptor on the other.
    #[test]
    fn a_descriptor_crosses_the_pair_and_still_works() {
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsFd;

        let (a, b) = pair().expect("socketpair");
        let mut file = tempfile::tempfile().expect("tempfile");
        file.write_all(b"carried").expect("write");
        file.rewind().expect("rewind");

        send(&a, b"take it", Some(file.as_fd())).expect("send");
        let (_, fd) = recv(&b).expect("recv").expect("not closed");

        let mut received = std::fs::File::from(fd.expect("a descriptor must arrive"));
        let mut text = String::new();
        received.read_to_string(&mut text).expect("read");
        assert_eq!(text, "carried");
    }

    /// SCM_RIGHTS does not inherit sender FD flags. The receive operation
    /// must set CLOEXEC atomically on the installed descriptor.
    #[cfg(target_os = "linux")]
    #[test]
    fn received_descriptor_is_close_on_exec_even_when_sender_is_not() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        use std::os::fd::AsFd;

        let (a, b) = pair().expect("socketpair");
        let file = tempfile::tempfile().expect("tempfile");
        fcntl(file.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).expect("clear sender CLOEXEC");
        send(&a, b"descriptor", Some(file.as_fd())).expect("send");
        let (_, received) = recv(&b).expect("recv").expect("open peer");
        let received = received.expect("SCM_RIGHTS descriptor");
        let flags = fcntl(received.as_raw_fd(), FcntlArg::F_GETFD).expect("get receiver flags");
        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
    }

    /// Message boundaries are the kernel's, not ours: two sends are two
    /// receives, never one concatenated read.
    #[test]
    fn boundaries_are_preserved() {
        let (a, b) = pair().expect("socketpair");
        send(&a, b"first", None).expect("send");
        send(&a, b"second", None).expect("send");
        assert_eq!(recv(&b).expect("recv").expect("open").0, b"first");
        assert_eq!(recv(&b).expect("recv").expect("open").0, b"second");
    }

    /// A closed peer is a fact to act on, not an error to report: it is how
    /// each half learns the other died.
    #[test]
    fn a_closed_peer_reads_as_none() {
        let (a, b) = pair().expect("socketpair");
        drop(a);
        assert!(recv(&b).expect("recv must not fail").is_none());
    }

    /// Close-on-exec is a security property once the next slice has the
    /// helper fork and exec processes on behalf of other accounts: a
    /// descriptor to this seam must never survive into one of those. This
    /// reads the kernel-reported flag itself rather than trusting that
    /// `pair()` passed `SOCK_CLOEXEC` -- a refactor to a two-step
    /// create-then-`fcntl` (or one that drops the flag) would leave `pair`
    /// looking the same while failing this.
    #[test]
    fn both_ends_are_close_on_exec() {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};

        let (a, b) = pair().expect("socketpair");
        for sock in [&a, &b] {
            let raw = fcntl(sock.as_raw_fd(), FcntlArg::F_GETFD).expect("fcntl(F_GETFD)");
            let flags = FdFlag::from_bits_truncate(raw);
            assert!(
                flags.contains(FdFlag::FD_CLOEXEC),
                "fd {} is missing FD_CLOEXEC: {flags:?}",
                sock.as_raw_fd()
            );
        }
    }

    /// A second descriptor riding along in one message is a protocol
    /// violation on this seam -- `recv` keeps only the first `ScmRights`
    /// entry and lets the rest fall out of scope at the end of its loop
    /// body, which closes them. That "closes" is checked by counting this
    /// process's open descriptors before and after the receive, but this
    /// test binary runs many tests in parallel, and another test opening or
    /// closing an unrelated descriptor in the same instant would make a
    /// process-wide count meaningless (this raced in practice while writing
    /// it). So the actual check lives in `..._body`, `#[ignore]`d out of the
    /// normal sweep, and this test re-invokes the test binary selecting
    /// only that one test -- a process with no sibling test to race.
    #[test]
    fn a_second_descriptor_in_one_message_is_not_leaked() {
        // Kept as one named constant, not inlined into `.args`, because the
        // failure message below quotes it: whoever renames the `_body` test
        // needs the exact string that must change to match.
        const INNER: &str =
            "helper::channel::tests::a_second_descriptor_in_one_message_is_not_leaked_body";

        let exe = std::env::current_exe().expect("current_exe");
        let output = std::process::Command::new(exe)
            .args([INNER, "--exact", "--ignored", "--test-threads=1"])
            .output()
            .expect("spawn the isolated leak check");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // A `--exact` filter that matches nothing still prints
        // "running 0 tests" / "test result: ok. 0 passed; ..." and exits 0
        // -- so `output.status.success()` alone cannot tell a real pass
        // from `INNER` having been renamed or deleted out from under this
        // string, which would silently disarm the whole check. Requiring
        // "running 1 test" catches exactly that: it fails loudly, naming
        // the test that needs to exist, instead of passing on zero tests.
        assert!(
            stdout.contains("running 1 test\n"),
            "expected the filter to match exactly one test, but it matched \
             none -- `{INNER}` does not exist under that name any more \
             (renamed, moved, or deleted?). Update the constant above to \
             match, or this check silently stops running.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );
        assert!(
            output.status.success(),
            "isolated leak check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}",
        );
    }

    /// The check itself: send two descriptors directly (bypassing `send`,
    /// which only ever offers one), and confirm the process's open-
    /// descriptor count grows by exactly one, not two. Only meaningful run
    /// alone -- see the test above, which is what actually runs it.
    #[test]
    #[ignore = "runs only via a_second_descriptor_in_one_message_is_not_leaked, in a process of its own"]
    fn a_second_descriptor_in_one_message_is_not_leaked_body() {
        let (a, b) = pair().expect("socketpair");
        let f1 = tempfile::tempfile().expect("f1");
        let f2 = tempfile::tempfile().expect("f2");
        let raw_fds = [f1.as_raw_fd(), f2.as_raw_fd()];
        let iov = [io::IoSlice::new(b"two")];
        let cmsg = [ControlMessage::ScmRights(&raw_fds)];
        sendmsg::<()>(a.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None).expect("sendmsg");

        let before = open_fd_count();
        let (_, fd) = recv(&b).expect("recv").expect("open");
        let after = open_fd_count();

        assert!(fd.is_some(), "the first descriptor must still arrive");
        assert_eq!(
            after,
            before + 1,
            "a second SCM_RIGHTS descriptor must be closed, not leaked"
        );
    }

    /// This process's current count of open file descriptors, for asserting
    /// on the delta a single operation leaves behind.
    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .count()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod monitor_ancillary_tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn monitor40_ancillary_ownership_isolated() {
        const BODY: &str =
            "helper::channel::monitor_ancillary_tests::monitor40_ancillary_ownership_body";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", BODY, "--ignored", "--test-threads=1"])
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
            "owned ancillary control failed: stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    #[ignore = "runs only in the owned ancillary control process"]
    fn monitor40_ancillary_ownership_body() {
        fn count() -> usize {
            std::fs::read_dir("/proc/self/fd").unwrap().count()
        }
        let selected = std::env::var("QSH_TEST_ANCILLARY_MODE").ok();
        for mode in [
            "credential-fd",
            "zero",
            "zero-credentialed",
            "payload-truncated",
            "control-truncated",
        ] {
            if selected.as_deref().is_some_and(|value| value != mode) {
                continue;
            }
            let (sender, receiver) = pair().unwrap();
            if mode != "zero" {
                nix::sys::socket::setsockopt(&receiver, nix::sys::socket::sockopt::PassCred, &true)
                    .unwrap();
            }
            let file = tempfile::tempfile().unwrap();
            let bytes = match mode {
                "zero" | "zero-credentialed" => Vec::new(),
                "payload-truncated" => vec![b'x'; MAX_MESSAGE_LEN + 1],
                _ => b"open".to_vec(),
            };
            if mode == "control-truncated" {
                let rights = [file.as_raw_fd(); 16];
                sendmsg::<()>(
                    sender.as_raw_fd(),
                    &[io::IoSlice::new(&bytes)],
                    &[ControlMessage::ScmRights(&rights)],
                    MsgFlags::empty(),
                    None,
                )
                .unwrap();
            } else {
                send(&sender, &bytes, Some(file.as_fd())).unwrap();
            }
            let before = count();
            let result = recv_once(&receiver);
            let after = count();
            match mode {
                "credential-fd" => {
                    let (payload, fd) = result.unwrap().unwrap();
                    assert_eq!(payload, b"open");
                    assert!(fd.is_some());
                    assert_eq!(after, before + 1);
                    drop(fd);
                }
                "zero" | "zero-credentialed" => {
                    assert!(result.unwrap().is_none());
                    assert_eq!(after, before, "zero packet must close installed rights");
                }
                _ => {
                    assert!(
                        matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData),
                        "mode={mode}"
                    );
                    assert_eq!(
                        after, before,
                        "rejected packet must close installed rights: {mode}"
                    );
                }
            }
            assert_eq!(count(), before, "no descriptor debt survives: {mode}");
        }
    }
}
