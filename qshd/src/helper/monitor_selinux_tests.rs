use super::*;
use crate::helper::selinux_tty::{Adapter, Prepared, Snapshot};
use std::ffi::CStr;
use std::io;

struct RestoreError;
impl Adapter for RestoreError {
    fn enabled(&self) -> io::Result<bool> {
        Ok(true)
    }
    fn selected(&self) -> io::Result<Option<CString>> {
        Ok(Some(CString::new("selected").unwrap()))
    }
    fn label(&self, _: RawFd) -> io::Result<CString> {
        Ok(CString::new("original").unwrap())
    }
    fn compute(&self, _: &CStr, _: &CStr) -> io::Result<CString> {
        Ok(CString::new("derived").unwrap())
    }
    fn set(&self, _: RawFd, context: &CStr) -> io::Result<()> {
        if context.to_bytes() == b"original" {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic restoration failure",
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn selinux_restore_error_keeps_exact_physical_kind_and_sticky_summary() {
    for kind in [CleanupKind::NoChild, CleanupKind::Reaped] {
        let (sender, receiver) = channel::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (slave, _peer) = UnixStream::pair().unwrap();
        let raw = slave.as_raw_fd();
        let snapshot = Snapshot::SelectedContext(CString::new("selected").unwrap());
        let Prepared::Relabeled(guard) =
            Prepared::prepare(&RestoreError, &snapshot, slave.into()).unwrap()
        else {
            panic!("missing guard")
        };
        let mut summary = CleanupSummary::default();
        report_terminal_cleanup(&sender, 810, kind, Some(guard), &mut summary);
        let (bytes, fd) = channel::recv(&receiver).unwrap().unwrap();
        assert!(fd.is_none());
        let failure = CleanupFailure::PtyLabelRestore {
            errno: nix::libc::EIO,
        };
        assert!(
            matches!(decode::<MonitorEvent>(&bytes).unwrap(), MonitorEvent::CleanupFailed { id:810, kind:actual, failure:actual_failure } if actual==kind && actual_failure==failure)
        );
        assert_eq!(summary.failure, Some(failure));
        assert_eq!(
            nix::fcntl::fcntl(raw, nix::fcntl::FcntlArg::F_GETFD),
            Err(nix::errno::Errno::EBADF)
        );
    }
}

#[test]
fn selinux_absent_guard_preserves_ordinary_cleanup_receipt() {
    let (sender, receiver) = channel::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut summary = CleanupSummary::default();
    report_terminal_cleanup::<RestoreError>(&sender, 811, CleanupKind::Reaped, None, &mut summary);
    let (bytes, _) = channel::recv(&receiver).unwrap().unwrap();
    assert!(matches!(
        decode::<MonitorEvent>(&bytes).unwrap(),
        MonitorEvent::CleanupComplete {
            id: 811,
            kind: CleanupKind::Reaped
        }
    ));
    assert_eq!(summary.failure, None);
}
