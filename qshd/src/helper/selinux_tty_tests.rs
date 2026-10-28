use super::*;
use std::cell::RefCell;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Operation(Operation),
    Restore,
}

struct Fake {
    enabled: io::Result<bool>,
    selected: Option<CString>,
    fail: Option<Operation>,
    fail_restore: bool,
    calls: RefCell<Vec<(Call, RawFd, Vec<u8>)>>,
}
impl Fake {
    fn selected() -> Self {
        Self {
            enabled: Ok(true),
            selected: Some(CString::new("selected").unwrap()),
            fail: None,
            fail_restore: false,
            calls: RefCell::new(vec![]),
        }
    }
    fn record(&self, op: Operation, fd: RawFd, value: &[u8]) -> io::Result<()> {
        self.calls
            .borrow_mut()
            .push((Call::Operation(op), fd, value.to_vec()));
        if self.fail == Some(op) {
            Err(io::Error::from_raw_os_error(13))
        } else {
            Ok(())
        }
    }
}
impl Adapter for Fake {
    fn enabled(&self) -> io::Result<bool> {
        self.record(Operation::Enabled, -1, b"")?;
        self.enabled
            .as_ref()
            .copied()
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error().unwrap()))
    }
    fn selected(&self) -> io::Result<Option<CString>> {
        self.record(Operation::SelectedContext, -1, b"")?;
        Ok(self.selected.clone())
    }
    fn label(&self, fd: RawFd) -> io::Result<CString> {
        self.record(Operation::ReadLabel, fd, b"")?;
        Ok(CString::new(format!("original-{fd}")).unwrap())
    }
    fn compute(&self, selected: &CStr, original: &CStr) -> io::Result<CString> {
        assert_eq!(selected.to_bytes(), b"selected");
        self.record(Operation::ComputeLabel, -1, original.to_bytes())?;
        Ok(CString::new("derived").unwrap())
    }
    fn set(&self, fd: RawFd, context: &CStr) -> io::Result<()> {
        if context.to_bytes() == b"derived" {
            self.record(Operation::SetLabel, fd, context.to_bytes())
        } else {
            self.calls
                .borrow_mut()
                .push((Call::Restore, fd, context.to_bytes().to_vec()));
            if self.fail_restore {
                Err(io::Error::from_raw_os_error(13))
            } else {
                Ok(())
            }
        }
    }
}
fn fd() -> OwnedFd {
    let (a, _b) = UnixStream::pair().unwrap();
    a.into()
}
fn closed(fd: RawFd) -> bool {
    unsafe extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    unsafe { fcntl(fd, 1) == -1 && io::Error::last_os_error().raw_os_error() == Some(9) }
}
fn selected() -> Snapshot {
    Snapshot::SelectedContext(CString::new("selected").unwrap())
}

#[test]
fn disabled_and_enabled_without_selection_are_distinct_and_do_not_touch_labels() {
    let mut fake = Fake::selected();
    fake.enabled = Ok(false);
    assert!(matches!(capture(&fake).unwrap(), Snapshot::Disabled));
    assert_eq!(fake.calls.borrow().len(), 1);
    fake.enabled = Ok(true);
    fake.selected = None;
    assert!(matches!(
        capture(&fake).unwrap(),
        Snapshot::EnabledWithoutSelection
    ));
    for snapshot in [Snapshot::Disabled, Snapshot::EnabledWithoutSelection] {
        fake.calls.borrow_mut().clear();
        let f = fd();
        let raw = f.as_raw_fd();
        let prepared = Prepared::prepare(&fake, &snapshot, f).unwrap();
        let unchanged = match prepared {
            Prepared::Unchanged(fd) => fd,
            Prepared::Relabeled(_) => panic!("inactive state must transfer the unchanged owner"),
        };
        assert_eq!(unchanged.as_raw_fd(), raw);
        assert!(!closed(raw));
        // The original consuming fork path owns this FD, not a retained guard.
        drop(unchanged);
        assert!(closed(raw));
        assert!(fake.calls.borrow().is_empty());
    }
}
#[test]
fn enabled_and_context_syscall_errors_are_not_disabled() {
    for op in [Operation::Enabled, Operation::SelectedContext] {
        let mut fake = Fake::selected();
        fake.fail = Some(op);
        let err = capture(&fake).unwrap_err();
        assert_eq!(err.operation, op);
        assert_eq!(err.error.raw_os_error(), Some(13));
    }
    assert!(matches!(
        capture(&Fake::selected()).unwrap(),
        Snapshot::SelectedContext(_)
    ));
}
#[test]
fn read_and_compute_failure_close_without_attempting_mutation() {
    for op in [Operation::ReadLabel, Operation::ComputeLabel] {
        let mut fake = Fake::selected();
        fake.fail = Some(op);
        let f = fd();
        let raw = f.as_raw_fd();
        let err = match Prepared::prepare(&fake, &selected(), f) {
            Err(e) => e,
            Ok(_) => panic!("unexpected guard"),
        };
        assert_eq!(err.operation, op);
        assert_eq!(err.error.raw_os_error(), Some(13));
        assert!(matches!(err.rollback, Rollback::NotRequired));
        assert!(closed(raw));
        assert!(!fake
            .calls
            .borrow()
            .iter()
            .any(|x| matches!(x.0, Call::Operation(Operation::SetLabel) | Call::Restore)));
    }
}
#[test]
fn failed_set_attempts_original_fd_rollback_and_always_closes() {
    for fail_restore in [false, true] {
        let mut fake = Fake::selected();
        fake.fail = Some(Operation::SetLabel);
        fake.fail_restore = fail_restore;
        let f = fd();
        let raw = f.as_raw_fd();
        let err = match Prepared::prepare(&fake, &selected(), f) {
            Err(e) => e,
            Ok(_) => panic!("unexpected guard"),
        };
        assert_eq!(err.operation, Operation::SetLabel);
        match err.rollback {
            Rollback::Restored => assert!(!fail_restore),
            Rollback::Failed(e) => {
                assert!(fail_restore);
                assert_eq!(e.raw_os_error(), Some(13));
            }
            Rollback::NotRequired => panic!("missing rollback"),
        }
        assert!(closed(raw));
        let calls = fake.calls.borrow();
        let last = calls.last().unwrap();
        assert_eq!(last.0, Call::Restore);
        assert_eq!(last.1, raw);
        assert_eq!(last.2, format!("original-{raw}").as_bytes());
    }
}
#[test]
fn explicit_finish_restores_exact_fd_and_closes_even_on_error() {
    for fail_restore in [false, true] {
        let mut fake = Fake::selected();
        fake.fail_restore = fail_restore;
        let f = fd();
        let raw = f.as_raw_fd();
        let guard = active(Prepared::prepare(&fake, &selected(), f).unwrap());
        assert!(!closed(raw));
        match guard.finish() {
            Finish::Restored => assert!(!fail_restore),
            Finish::RestoreFailed(e) => {
                assert!(fail_restore);
                assert_eq!(e.raw_os_error(), Some(13));
            }
            Finish::Unchanged => panic!("missing restoration"),
        }
        assert!(closed(raw));
        assert_eq!(
            fake.calls
                .borrow()
                .iter()
                .filter(|x| x.0 == Call::Restore)
                .count(),
            1
        );
    }
}
#[test]
fn parallel_guards_keep_originals_and_lifetimes_independent() {
    let fake = Fake::selected();
    let a = fd();
    let b = fd();
    let ar = a.as_raw_fd();
    let br = b.as_raw_fd();
    assert_ne!(ar, br);
    let ag = active(Prepared::prepare(&fake, &selected(), a).unwrap());
    let bg = active(Prepared::prepare(&fake, &selected(), b).unwrap());
    assert!(matches!(ag.finish(), Finish::Restored));
    assert!(closed(ar));
    assert!(!closed(br));
    assert!(matches!(bg.finish(), Finish::Restored));
    assert!(closed(br));
    let calls = fake.calls.borrow();
    for raw in [ar, br] {
        assert!(calls.iter().any(|x| x.0 == Call::Restore
            && x.1 == raw
            && x.2 == format!("original-{raw}").as_bytes()));
    }
}

#[test]
fn borrowed_descriptor_does_not_transfer_guard_ownership() {
    let fake = Fake::selected();
    let owned = fd();
    let raw = owned.as_raw_fd();
    let guard = active(Prepared::prepare(&fake, &selected(), owned).unwrap());
    assert_eq!(guard.as_fd().as_raw_fd(), raw);
    assert!(!closed(raw));
    assert!(matches!(guard.finish(), Finish::Restored));
    assert!(closed(raw));
}

#[test]
fn abandoning_guard_is_emergency_cleanup_not_an_explicit_receipt() {
    let mut fake = Fake::selected();
    fake.fail_restore = true;
    let owned = fd();
    let raw = owned.as_raw_fd();
    drop(active(
        Prepared::prepare(&fake, &selected(), owned).unwrap(),
    ));
    assert!(closed(raw));
    assert_eq!(
        fake.calls
            .borrow()
            .iter()
            .filter(|x| x.0 == Call::Restore)
            .count(),
        1
    );
}

fn active<A: Adapter>(prepared: Prepared<'_, A>) -> Guard<'_, A> {
    match prepared {
        Prepared::Relabeled(guard) => guard,
        Prepared::Unchanged(_) => panic!("selected context did not produce a guard"),
    }
}

fn pty() -> (std::fs::File, OwnedFd) {
    use std::os::fd::FromRawFd;
    #[link(name = "util")]
    unsafe extern "C" {
        fn openpty(
            master: *mut i32,
            slave: *mut i32,
            name: *mut i8,
            term: *const (),
            size: *const (),
        ) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: valid output storage, optional name/termios/winsize omitted.
    assert_eq!(
        unsafe {
            openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: successful openpty transferred both fresh descriptor owners.
    let (master, slave) = unsafe {
        (
            std::fs::File::from_raw_fd(master),
            OwnedFd::from_raw_fd(slave),
        )
    };
    // Linux F_GETFL/F_SETFL and O_NONBLOCK; bounded read observation, no waits.
    let flags = unsafe { fcntl(master.as_raw_fd(), 3) };
    assert!(flags >= 0);
    assert_eq!(unsafe { fcntl(master.as_raw_fd(), 4, flags | 0x800) }, 0);
    // Explicitly establish the same invariant as MSG_CMSG_CLOEXEC at reception.
    assert_eq!(unsafe { fcntl(slave.as_raw_fd(), 2, 1) }, 0);
    (master, slave)
}
fn master_error(master: &mut std::fs::File) -> i32 {
    use std::io::Read;
    master
        .read(&mut [0u8; 1])
        .unwrap_err()
        .raw_os_error()
        .unwrap()
}
#[test]
fn inactive_parent_slave_closes_without_waiting_for_scope_finish() {
    let fake = Fake::selected();
    for snapshot in [Snapshot::Disabled, Snapshot::EnabledWithoutSelection] {
        let (mut master, slave) = pty();
        let prepared = Prepared::prepare(&fake, &snapshot, slave).unwrap();
        let slave = match prepared {
            Prepared::Unchanged(fd) => fd,
            Prepared::Relabeled(_) => panic!("inactive guard"),
        };
        assert_eq!(master_error(&mut master), 11); // EAGAIN: live slave.
        drop(slave); // Original consuming-fork parent's close, no scope guard.
        assert_eq!(master_error(&mut master), 5); // EIO: no slave remains.
    }
}
#[test]
fn active_guard_finish_releases_delayed_terminal_eof_even_on_restore_failure() {
    for fail_restore in [false, true] {
        let mut fake = Fake::selected();
        fake.fail_restore = fail_restore;
        let (mut master, slave) = pty();
        let guard = active(Prepared::prepare(&fake, &selected(), slave).unwrap());
        let fork_input = guard.as_fd().try_clone_to_owned().unwrap();
        assert_eq!(master_error(&mut master), 11);
        drop(fork_input); // Original consuming fork path released its owner.
        assert_eq!(master_error(&mut master), 11); // Guard deliberately retains slave.
        match guard.finish() {
            Finish::Restored => assert!(!fail_restore),
            Finish::RestoreFailed(_) => assert!(fail_restore),
            Finish::Unchanged => panic!("active guard lost original"),
        }
        assert_eq!(master_error(&mut master), 5); // Released before cleanup publication.
    }
}
