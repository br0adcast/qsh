//! Per-descriptor SELinux terminal ownership, independent of monitor policy.
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

#[derive(Debug)]
pub(crate) enum Snapshot {
    Disabled,
    EnabledWithoutSelection,
    SelectedContext(CString),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Enabled,
    SelectedContext,
    ReadLabel,
    ComputeLabel,
    SetLabel,
}
#[derive(Debug)]
pub(crate) struct CaptureFailure {
    pub operation: Operation,
    pub error: io::Error,
}
#[derive(Debug)]
pub(crate) enum Rollback {
    NotRequired,
    Restored,
    Failed(io::Error),
}
#[derive(Debug)]
pub(crate) struct PrepareFailure {
    pub operation: Operation,
    pub error: io::Error,
    pub rollback: Rollback,
}
#[derive(Debug)]
pub(crate) enum Finish {
    Unchanged,
    Restored,
    RestoreFailed(io::Error),
}

pub(crate) trait Adapter {
    fn enabled(&self) -> io::Result<bool>;
    fn selected(&self) -> io::Result<Option<CString>>;
    fn label(&self, fd: RawFd) -> io::Result<CString>;
    fn compute(&self, selected: &CStr, original: &CStr) -> io::Result<CString>;
    fn set(&self, fd: RawFd, context: &CStr) -> io::Result<()>;
}
pub(crate) fn capture(adapter: &impl Adapter) -> Result<Snapshot, CaptureFailure> {
    if !adapter.enabled().map_err(|error| CaptureFailure {
        operation: Operation::Enabled,
        error,
    })? {
        return Ok(Snapshot::Disabled);
    }
    Ok(
        match adapter.selected().map_err(|error| CaptureFailure {
            operation: Operation::SelectedContext,
            error,
        })? {
            Some(context) => Snapshot::SelectedContext(context),
            None => Snapshot::EnabledWithoutSelection,
        },
    )
}
pub(crate) struct Guard<'a, A: Adapter> {
    adapter: &'a A,
    fd: Option<OwnedFd>,
    original: Option<CString>,
}
/// Only a successful selected-context mutation retains a restoration owner.
/// The input must already be CLOEXEC at the ancillary-receive/fork seam;
/// OwnedFd alone does not establish that property.
pub(crate) enum Prepared<'a, A: Adapter> {
    Unchanged(OwnedFd),
    Relabeled(Guard<'a, A>),
}
impl<'a, A: Adapter> Prepared<'a, A> {
    pub(crate) fn prepare(
        adapter: &'a A,
        snapshot: &Snapshot,
        fd: OwnedFd,
    ) -> Result<Self, PrepareFailure> {
        let Snapshot::SelectedContext(selected) = snapshot else {
            // Inactive paths keep the original consuming fork/close lifetime.
            // They cannot be retained as a per-channel restoration guard.
            return Ok(Self::Unchanged(fd));
        };
        let original = adapter
            .label(fd.as_raw_fd())
            .map_err(|error| PrepareFailure {
                operation: Operation::ReadLabel,
                error,
                rollback: Rollback::NotRequired,
            })?;
        let derived = adapter
            .compute(selected, &original)
            .map_err(|error| PrepareFailure {
                operation: Operation::ComputeLabel,
                error,
                rollback: Rollback::NotRequired,
            })?;
        if let Err(error) = adapter.set(fd.as_raw_fd(), &derived) {
            let rollback = match adapter.set(fd.as_raw_fd(), &original) {
                Ok(()) => Rollback::Restored,
                Err(error) => Rollback::Failed(error),
            };
            // Close the exact owner before publishing the failure/rollback result.
            drop(fd);
            return Err(PrepareFailure {
                operation: Operation::SetLabel,
                error,
                rollback,
            });
        }
        Ok(Self::Relabeled(Guard {
            adapter,
            fd: Some(fd),
            original: Some(original),
        }))
    }
}
impl<A: Adapter> Guard<'_, A> {
    pub(crate) fn finish(mut self) -> Finish {
        self.finish_inner()
    }
    fn finish_inner(&mut self) -> Finish {
        let outcome = match (self.fd.as_ref(), self.original.take()) {
            (Some(fd), Some(original)) => match self.adapter.set(fd.as_raw_fd(), &original) {
                Ok(()) => Finish::Restored,
                Err(error) => Finish::RestoreFailed(error),
            },
            _ => Finish::Unchanged,
        };
        // Restoration failure does not pin a slave forever or conceal closure.
        drop(self.fd.take());
        outcome
    }
}
#[cfg(test)]
#[path = "selinux_tty_tests.rs"]
mod tests;

impl<A: Adapter> AsFd for Guard<'_, A> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd
            .as_ref()
            .expect("a live guard owns its descriptor")
            .as_fd()
    }
}
impl<A: Adapter> Drop for Guard<'_, A> {
    fn drop(&mut self) {
        // Emergency cleanup only. Callers must consume finish() and account for
        // its outcome before publishing success; Drop provides no receipt.
        let _ = self.finish_inner();
    }
}

#[path = "selinux_tty_native.rs"]
mod native;

pub(crate) use native::Native;
pub(crate) static NATIVE: Native = Native;
