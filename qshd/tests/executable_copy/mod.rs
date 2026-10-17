//! A copy of an executable that can be run at once, for the tests that run
//! `qshd` from a directory of their own.
//!
//! `std::fs::copy` writes the copy through a descriptor of this process. The
//! test harness runs tests on several threads, and any of them may spawn a
//! process meanwhile: the child starts with a copy of every descriptor this
//! process has, the copy's write descriptor among them, and holds it until
//! it execs -- close-on-exec closes it only then. If this thread execs the
//! copy inside that window the kernel refuses with `ETXTBSY` ("Text file
//! busy"): the file is still open for writing somewhere. Under a loaded
//! machine the window between a child's fork and its exec is long enough to
//! hit, and the full workspace run did.
//!
//! Writing to a temporary name and renaming the result into place does not
//! help: the rename keeps the file (the inode), and the inherited
//! descriptor is still open on it. So the copy is made by a child process
//! (`cp`) instead: the only write descriptor ever open on the copy belongs
//! to that child, no thread of this process can hand it on, and it is gone
//! when `cp` has exited, which `status` waits for.

use std::path::Path;
use std::process::Command;

/// Copies the executable `from` to `to` (mode included) and returns once
/// nothing holds `to` open for writing, so it can be run at once.
pub fn copy_executable(from: &Path, to: &Path) {
    let status = Command::new("cp")
        .arg("--")
        .arg(from)
        .arg(to)
        .status()
        .expect("run cp");
    assert!(
        status.success(),
        "cp {} {} failed: {status:?}",
        from.display(),
        to.display()
    );
}
