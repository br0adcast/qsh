//! The other half of the invariant `helper/mod.rs` states: after
//! `qshd serve --system` splits, the privileged helper must hold no
//! network descriptor at all -- only the worker does. It holds today only
//! because of one closure's capture list (`split_and_run` explicitly drops
//! `run_worker`, which owns the UDP socket, in the parent branch); binding
//! the socket inside the closure instead, or giving it a second owner,
//! would break that silently, with nothing else here to notice.
//!
//! This drives a REAL `qshd serve --system` process (not
//! `helper::split_and_run` called in-process, which would fork the test
//! binary itself -- every thread, every other test's open files, all of
//! it) and inspects the resulting helper's `/proc/<pid>/fd` table from the
//! outside while it is still alive. There is no way to ask the helper to
//! make this assertion of itself: its branch of `split_and_run` never
//! returns (`server::run` is `-> !`), so no code running inside that
//! process ever gets control back.
//!
//! `#![cfg(feature = "system")]` on the whole file: without the feature,
//! `qshd serve --system` is refused outright (a plain CLI error, not this
//! process's fd table), so there is nothing here worth compiling, and
//! leaving the file's helpers in unconditionally would make every one of
//! them dead code under `-D warnings` whenever this crate is tested without
//! the feature -- exactly the build the default (non-system) binary uses.
//!
//! Starting the daemon and reading its startup banner used to be duplicated
//! here; that piece (plus its port-race retry, added for
//! `system_mode_shell.rs`) now lives once, in `tests/common/mod.rs`.
//!
//! Since Task 2 of the system-mode-slice3 plan, every test below that
//! expects `start_daemon` to actually print a banner installs the shipped
//! `/etc/pam.d/qshd` first (`common::install_service_file`) -- otherwise
//! the daemon now refuses to start at all (`refuse_without_pam_service` in
//! `serve.rs`). That write lands on the machine's real file, the one every
//! `qshd` on it reads, exactly as `system_mode_pam.rs` and
//! `system_mode_accounts.rs` already warn about -- so, like them, this file
//! runs its bodies through `common::on_a_disposable_host`: root AND
//! `QSHD_TEST_DISPOSABLE_HOST=1`, which only a disposable container may
//! set, or a loud `SKIPPED` line and nothing touched. No account is
//! created here, but the write is exactly as irreversible on a host anyone
//! keeps. Run it like this, from the repository's root:
//!
//! ```text
//! cargo test -p qshd --features system --test serve_system_split --locked --no-run
//! docker run --rm --init --cap-add=SYS_PTRACE -e QSHD_TEST_DISPOSABLE_HOST=1 \
//!     -v "$PWD:$PWD:ro" -w "$PWD" ubuntu:24.04 \
//!     "$PWD/target/debug/deps/serve_system_split-<hash>" --test-threads=1 --nocapture
//! ```
//!
//! - `--cap-add=SYS_PTRACE`: without it,
//!   `the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open` and
//!   `the_worker_ends_itself_when_only_its_authentication_seam_is_lost` fail
//!   on `pidfd_getfd ... Operation not permitted` -- Docker's default
//!   seccomp profile refusing it the same access `ptrace(2)` would need,
//!   nothing to do with PAM or with this file's own logic.
//! - `--test-threads=1`: several tests here read `/proc` across the whole
//!   container while another is mid-fork, and that cross-test interference
//!   fails most runs at the default thread count -- pre-existing, and
//!   present at this file's own BASE too, not something this change
//!   introduced.
//! - The repository is mounted read-only at its own absolute path (the
//!   binary has `qshd`'s path baked in via `CARGO_BIN_EXE_qshd`) and
//!   `--init` reaps what a killed daemon leaves behind, exactly as
//!   `system_mode_accounts.rs` explains.

#![cfg(feature = "system")]

mod common;

use std::collections::HashSet;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use qshd::helper::spawner::{AUTH_READER_THREAD, AUTH_SEAM_CLOSED_LOG, MAX_THREAD_NAME_LEN};

/// What every root-gated test in this file does to the machine it runs on,
/// for the loud `SKIPPED` line (see `common::on_a_disposable_host`): no
/// account, but -- since Task 2 of slice 3 -- the machine's real
/// `/etc/pam.d/qshd`, installed so the real `qshd serve --system` each test
/// spawns can start at all. `a_thread_name_linux_would_cut_is_refused_at_once`
/// needs neither root nor a daemon, so it stays outside this gate.
const WHAT_THESE_TESTS_DO: &str =
    "starts a real `qshd serve --system` daemon, installing the machine's /etc/pam.d/qshd so it can";

/// Every INET socket inode this pid's network namespace reports, from
/// `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` -- the fourth column format
/// documented in `proc(5)`, the last of which (index 9 once split on
/// whitespace) is the socket's inode number.
fn inet_socket_inodes(pid: u32) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    for proto in ["tcp", "tcp6", "udp", "udp6"] {
        let Ok(contents) = std::fs::read_to_string(format!("/proc/{pid}/net/{proto}")) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            if let Some(inode) = line.split_whitespace().nth(9).and_then(|s| s.parse().ok()) {
                inodes.insert(inode);
            }
        }
    }
    inodes
}

/// The socket inode each of this pid's open file descriptors names, read
/// from `/proc/<pid>/fd/*` -- each entry a symlink reading `socket:[N]` for
/// a socket, something else (a regular file, a pipe, ...) for every other
/// kind of descriptor, which this simply skips.
fn open_socket_inodes(pid: u32) -> Vec<u64> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read the process's fd table")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

/// The state of `/proc/<pid>/task/<pid>/children`, distinguishing three
/// cases fix round 2 found conflated into one path in an earlier version of
/// this file: the file might not exist at all (this kernel lacks
/// `CONFIG_PROC_CHILDREN` -- nothing below can check anything, and skipping
/// is the honest response), it might exist but be empty (the helper has not
/// forked yet, or never will -- worth a bounded RETRY, not an immediate
/// skip: `start_daemon` returns as soon as the pre-fork startup banner
/// prints, which races the fork itself, not just this file read), or it
/// might name a pid.
enum ChildrenProbe {
    Unsupported,
    Empty,
    /// Every pid the file named, in the order it named them -- not just the
    /// first. Reading only the first is what let a caller take a pid that
    /// was never the worker: see [`wait_for_worker_pid`].
    Children(Vec<u32>),
}

fn probe_children(helper_pid: u32) -> ChildrenProbe {
    match std::fs::read_to_string(format!("/proc/{helper_pid}/task/{helper_pid}/children")) {
        // ONLY a missing file means "this kernel has no CONFIG_PROC_CHILDREN"
        // and so justifies the skip below. Any other error -- the helper
        // died and took its whole `/proc` entry with it, `/proc` is not
        // mounted, permission was refused -- is not that fact, and folding
        // it into the same answer would turn a real failure into a silent
        // skip. Those retry instead, and the caller's deadline turns a
        // permanent one into a loud panic naming what it saw.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ChildrenProbe::Unsupported,
        Err(_) => ChildrenProbe::Empty,
        Ok(contents) => {
            let pids: Vec<u32> = contents
                .split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect();
            if pids.is_empty() {
                ChildrenProbe::Empty
            } else {
                ChildrenProbe::Children(pids)
            }
        }
    }
}

/// How long these tests wait for the worker to appear, or for its identity
/// or liveness to change, before giving up -- generous, per this
/// codebase's own rule for timing-sensitive checks: a slow machine must
/// make a test using this slower, never flaky, and never silently pass for
/// having given up too soon. An earlier version of this file used a flat
/// 300ms sleep and a single, un-retried check instead -- exactly the shape
/// fix round 2 found could both pass for the wrong reason (see
/// `probe_children`'s docs) and prove nothing about the parent-death
/// signal specifically (see the death test below).
const WORKER_WAIT: Duration = Duration::from_secs(10);

/// Waits, bounded by [`WORKER_WAIT`], for the helper to have exactly one
/// child and to still have it a poll later -- which, before any login, is
/// the worker and can be nothing else. `None` means the kernel does not
/// expose `/proc/<pid>/task/<pid>/children` (needs `CONFIG_PROC_CHILDREN`)
/// -- the ONLY case worth a skip, since nothing below can check anything
/// without it. Anything else that never produces such a child is a
/// genuine failure, reported with a panic naming what was actually seen:
/// the daemon already proved it is alive (its startup banner is what got a
/// caller here at all), so a helper that never forks is a real bug, not an
/// unsupported kernel -- a silent skip here would be exactly the "passes
/// for the wrong reason" fix round 2 was written to close.
///
/// `helper::split_and_run` forks exactly once for the helper/worker split
/// itself. Every OTHER fork the helper makes belongs to a login -- the
/// process that reads an account's `authorized_keys` as that account
/// (`helper::authorized`), the one that verifies a proof
/// (`helper/server.rs`), and the login's monitor -- and the first two of
/// those are short-lived. A caller here has not logged in yet, so the
/// worker is the only child there SHOULD be; taking "the first pid in the
/// file" regardless was measured returning a pid that was gone moments
/// later, and every caller below then either read `/proc` for a process
/// that no longer existed or compared a stale number against a live child
/// list (which is how `a_monitor_holds_no_seam_and_the_worker_still_sees_the_end`
/// came to report "2 children besides its worker" -- its filter matched
/// none of them). So this insists on exactly one child and on that child
/// still being there, and waits rather than settling for whatever it saw
/// first.
fn wait_for_worker_pid(helper_pid: u32) -> Option<u32> {
    let deadline = Instant::now() + WORKER_WAIT;
    let mut last_seen = Vec::new();
    loop {
        match probe_children(helper_pid) {
            ChildrenProbe::Unsupported => return None,
            ChildrenProbe::Children(pids) => {
                // Exactly one, and still there on a second look: a pid that
                // survives a poll interval while no login is in flight is
                // the worker, not a fork on its way out.
                if let [only] = pids[..] {
                    std::thread::sleep(Duration::from_millis(20));
                    if probe_children(helper_pid).names(only) {
                        return Some(only);
                    }
                }
                last_seen = pids;
            }
            ChildrenProbe::Empty => last_seen.clear(),
        }
        assert!(
            Instant::now() < deadline,
            "the helper (pid {helper_pid}) never settled on a single, lasting child within \
             {WORKER_WAIT:?} -- the split does not seem to have happened at all (last children \
             seen: {last_seen:?})"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl ChildrenProbe {
    /// Whether this probe names `pid` as a child. An unreadable or empty
    /// file names nothing, which is the answer a caller wants when it is
    /// asking "is the process I am watching still the helper's child?"
    fn names(&self, pid: u32) -> bool {
        matches!(self, ChildrenProbe::Children(pids) if pids.contains(&pid))
    }
}

/// Waits, bounded by [`WORKER_WAIT`], for `worker_pid`'s real, effective,
/// saved AND filesystem uid to all read back as `target`'s. Right after the
/// fork the worker is still root for however long
/// `helper::drop_worker_privileges` takes, so reading
/// `/proc/<worker_pid>/status` once, immediately, would race that window
/// rather than prove where the worker actually lands -- the same class of
/// mistake `wait_for_worker_pid` exists to close on the fork side.
fn wait_for_worker_uid(
    worker_pid: u32,
    target: nix::unistd::Uid,
) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let deadline = Instant::now() + WORKER_WAIT;
    let mut last: Option<Vec<u32>> = None;
    loop {
        // A pid that has vanished is reported as such at the deadline, not
        // panicked over on the spot -- see `read_proc_status_ids`.
        if let Some(ids) = read_proc_status_ids(worker_pid) {
            if ids.0.iter().all(|&u| u == target.as_raw()) {
                return ids;
            }
            last = Some(ids.0);
        }
        if Instant::now() >= deadline {
            match last {
                Some(uids) => panic!(
                    "the worker (pid {worker_pid})'s uid never became {target} within \
                     {WORKER_WAIT:?}, last seen {uids:?}"
                ),
                None => panic!(
                    "the worker (pid {worker_pid}) was never there to read: /proc has no entry \
                     for it at any point in {WORKER_WAIT:?}, so it died (or was never the \
                     worker) before its uid could be checked"
                ),
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits, bounded by [`WORKER_WAIT`], until the worker is STRICTLY PAST its
/// SECOND `helper::arm_and_verify_pdeathsig` call -- the one after
/// `drop_worker_privileges` -- rather than merely "exists"
/// (`wait_for_worker_pid` alone) or "has dropped its uid"
/// (`wait_for_worker_uid` alone, whose CONDITION becomes true strictly
/// before the second arming -- the drop finishes, uid change included,
/// before `split_and_run`'s child branch reaches that call -- but whose
/// OBSERVATION of it, being a poll from another process, can land anywhere
/// after that, before or after the arming. That is exactly why "the uid
/// moved" is a necessary condition here and not a sufficient one).
///
/// This matters because the death test below kills the helper right after
/// this returns: killing any earlier races the worker's own progress
/// through the fix under test. Fix round 2's control run (re-arm deleted,
/// test observed failing) was real, but not GUARANTEED -- it only worked
/// because this test process happened to take longer to reach its own
/// `pidfd_getfd` call than the worker took to run a handful of local
/// syscalls, not because anything here made that so.
///
/// Two conditions, both required, so together they prove the second arming
/// call already returned successfully rather than merely probably having
/// had time to:
/// - the uid has moved to `target` (necessary: the drop must have
///   finished for the second arming to even be reached), and
/// - the worker has at least two threads. `split_and_run` only reaches
///   `spawner::worker_clients` (which starts the worker's second thread,
///   its channel seam's reader) AFTER the second arming call returns `Ok` --
///   if that call had failed, the `?` in `split_and_run` would have ended
///   the process before any second thread ever started.
///   Observing two-or-more threads from OUTSIDE the process is therefore
///   proof, not a probably-long-enough wait, that the call already
///   succeeded: `/proc` cannot report a thread that does not exist yet.
fn wait_until_worker_is_armed_the_second_time(worker_pid: u32, target: nix::unistd::Uid) {
    let deadline = Instant::now() + WORKER_WAIT;
    loop {
        // `None` -- the pid is gone -- is "not yet", never a panic from
        // here: the deadline below is what turns a pid that never comes
        // back into a failure, and it names what it saw.
        let uid_ok = read_proc_status_ids(worker_pid)
            .is_some_and(|ids| ids.0.iter().all(|&u| u == target.as_raw()));
        let thread_count = std::fs::read_dir(format!("/proc/{worker_pid}/task"))
            .map(|entries| entries.count())
            .unwrap_or(0);
        if uid_ok && thread_count >= 2 {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "the worker (pid {worker_pid}) never got past its second parent-death-signal \
                 registration within {WORKER_WAIT:?} (uid matched target: {uid_ok}, thread \
                 count: {thread_count}, wanted >= 2) -- it may be stuck inside \
                 drop_worker_privileges, or already gone"
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The full supplementary-group list `getgrouplist` would compute for
/// `login`, sorted -- the same computation `helper::account::lookup` (and,
/// through it, `helper::drop_worker_privileges`) makes, so comparing a
/// worker's actual `Groups:` line against THIS, rather than against just
/// the target account's own primary group, is what actually proves the
/// full group list took, not merely that the one group everyone expects
/// happened to be there.
fn expected_groups(login: &str, primary_gid: nix::unistd::Gid) -> Vec<u32> {
    let mut ids: Vec<u32> = nix::unistd::getgrouplist(
        &std::ffi::CString::new(login).expect("a login name has no interior NUL"),
        primary_gid,
    )
    .expect("getgrouplist for the target account")
    .iter()
    .map(|g| g.as_raw())
    .collect();
    ids.sort_unstable();
    ids
}

/// `pidfd_open(2)` (Linux 5.3+): a file descriptor referring to a process
/// by pid, usable with [`pidfd_getfd`] below. `nix` 0.28 has no wrapper for
/// either syscall, only `libc`'s raw numbers.
fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd> {
    // SAFETY: a plain syscall with no pointer arguments; `pid` is a plain
    // integer and flags `0` is documented as the only currently valid value.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative return from `pidfd_open` is a freshly opened
    // descriptor nothing else in this process holds yet -- ours to own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// `pidfd_getfd(2)` (Linux 5.6+): duplicates `target_fd` from the process
/// `pidfd` refers to into THIS process, as a new, independent descriptor
/// pointing at the SAME underlying open file description -- so closing the
/// target process's own copy (including by that process dying) does not
/// end the reference this duplicate holds. This is the mechanism the death
/// test below uses to keep the helper's end of the seam socket alive past
/// the helper's own death, the way a later slice's PAM child (forked
/// between the helper's fork and its exec, holding the same descriptor)
/// would for real.
fn pidfd_getfd(pidfd: BorrowedFd, target_fd: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: same as `pidfd_open` -- a plain syscall, no pointers in, and
    // a non-negative return is a fresh, owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target_fd, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// `pidfd_send_signal(2)` (Linux 5.1+): sends `signal` to the SPECIFIC
/// process instance `pidfd` refers to -- unlike `kill(pid, ...)`, immune to
/// that pid having already been reaped by its real parent (`init`, once
/// the helper it was reparented to is gone) and reused for an unrelated
/// process by the time this runs. Used only by the death test's own
/// cleanup guard, which must still be able to signal the worker safely
/// even long after the test function itself has returned or panicked.
fn pidfd_send_signal(pidfd: BorrowedFd, signal: nix::sys::signal::Signal) -> std::io::Result<()> {
    // SAFETY: a plain syscall; a null `info` is documented as valid (it
    // behaves as if the signal came from `kill(2)`), and `flags` is 0
    // because nothing here uses `PIDFD_SIGNAL_THREAD_GROUP`-style options.
    let res = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether `e` is `ENOSYS` -- the ONE failure mode that legitimately means
/// "this kernel does not have the syscall at all," worth a skip. Every
/// other error (most importantly `EPERM`, which Yama's `ptrace_scope=3` or
/// a container's seccomp profile can produce for `pidfd_getfd` specifically
/// -- it requires the same access `ptrace(2)` would by default) is a
/// different fact than "too old a kernel" and must fail loudly instead of
/// being folded into the same skip message.
fn is_enosys(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOSYS)
}

/// Finds exactly the helper's channel, authentication and diagnostic sockets.
/// Pair creation order identifies auth as the middle descriptor; the auth-loss
/// test independently proves that identity through the named reader's stderr.
/// An unexpected extra socket is a failure, never an arbitrary candidate choice.
fn seam_fd_numbers(pid: u32) -> [i32; 3] {
    let candidates: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap_or_else(|e| panic!("read /proc/{pid}/fd: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            std::fs::read_link(entry.path())
                .map(|target| target.to_string_lossy().starts_with("socket:["))
                .unwrap_or(false)
        })
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    match candidates[..] {
        [first, second, third] => [first, second, third],
        ref other => panic!(
            "the helper (pid {pid}) must hold exactly three AF_UNIX socket fds (channel, authentication and diagnostic seams) to duplicate unambiguously, found {}: {other:?}",
            other.len()
        ),
    }
}

/// Reads the `Uid:`, `Gid:` and `Groups:` lines of `/proc/<pid>/status`
/// (format documented in `proc(5)`: `Uid:` and `Gid:` each carry four
/// whitespace-separated numbers -- real, effective, saved-set, filesystem
/// -- and `Groups:` a whitespace-separated, possibly empty, list) as three
/// vectors of raw ids.
///
/// `None` when the file is not there to read: a pid can be reaped between
/// one poll of a waiting loop and the next, and `/proc` then answers
/// `ENOENT` for it. That is a fact about the moment, not a verdict, and a
/// panic raised from inside a polling helper spent the caller's whole
/// remaining deadline on one unlucky read -- measured, under load, as
/// `read /proc/<n>/status: No such file or directory` from three different
/// tests in this file. The callers below carry the deadline and the
/// sentence; this only reports what it saw.
///
/// A file that IS there but does not parse still panics: that is a
/// disagreement with `proc(5)`, not a race.
fn read_proc_status_ids(pid: u32) -> Option<(Vec<u32>, Vec<u32>, Vec<u32>)> {
    let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("read /proc/{pid}/status: {e}"),
    };
    let parse_after = |prefix: &str| -> Vec<u32> {
        status
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("no {prefix:?} line in /proc/{pid}/status: {status:?}"))
            .trim_start_matches(prefix)
            .split_whitespace()
            .map(|s| s.parse().unwrap_or_else(|e| panic!("id {s:?}: {e}")))
            .collect()
    };
    Some((
        parse_after("Uid:"),
        parse_after("Gid:"),
        parse_after("Groups:"),
    ))
}

/// Needs root: since Task 1 of the system-mode-slice2b plan
/// (`qshd/src/serve.rs`), `--system` refuses to start at all otherwise -- see
/// `common::start_daemon`'s docs. Skipped loudly rather than run when the
/// suite is not root, the way this plan's later, account-switching
/// acceptance test is designed to skip too.
#[test]
fn the_helper_holds_no_network_descriptor_after_the_split() {
    common::on_a_disposable_host(
        "the_helper_holds_no_network_descriptor_after_the_split",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            // No client ever connects in this test -- it only inspects the
            // helper's fd table from the outside -- so there is nothing to
            // list in `authorized_keys` (`start_daemon` warns about the
            // missing file rather than refusing to start over it), and the
            // port and server public key `start_daemon` hands back go
            // unused too.
            //
            // Since the system-mode-slice3 plan's Task 2, the daemon also
            // refuses to start at all without its own PAM service file
            // (`refuse_without_pam_service` in `serve.rs`) -- a
            // container's `/etc/pam.d` has no reason to carry `qshd` on
            // its own, so every test in this file that expects
            // `start_daemon` to actually print a banner installs the
            // shipped one first, the same way `system_mode_pam.rs` and
            // `system_mode_accounts.rs` do.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let (daemon, _server_pub, _port) = common::start_daemon(dir.path());
            let pid = daemon.child.id();

            // The startup banner already confirmed the pre-fork work
            // (binding the port, building `auth`) finished; the fork
            // itself is the very next thing `run_serve_command` does.
            // Generous rather than tight, per this codebase's own rule
            // for timing-sensitive checks: a slow machine must make this
            // test slower, never flaky.
            std::thread::sleep(Duration::from_millis(300));

            // A light corroborating check before the main one: the split
            // actually happened (there is a child of `pid`). Not every
            // kernel build exposes `task/<pid>/children` (it needs
            // `CONFIG_PROC_CHILDREN`), so its absence is skipped rather
            // than treated as a failure -- it says nothing about whether
            // the split happened, only that this particular way of asking
            // cannot see it here.
            if let Ok(children) =
                std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            {
                assert!(
                    !children.trim().is_empty(),
                    "the helper (pid {pid}) has no child process -- the split does not seem to \
                     have happened at all"
                );
            }
            // And the helper -- unlike the worker, which builds a tokio
            // runtime and a reader thread -- is still the single thread
            // `split_and_run` insisted on before it forked.
            let helper_threads = std::fs::read_dir(format!("/proc/{pid}/task"))
                .expect("read the helper's thread list")
                .count();
            assert_eq!(
                helper_threads, 1,
                "the helper (pid {pid}) must stay single-threaded for its whole life, found \
                 {helper_threads} threads"
            );

            // The main point: no INET socket among the helper's open
            // descriptors.
            let inet_inodes = inet_socket_inodes(pid);
            let leaked: Vec<u64> = open_socket_inodes(pid)
                .into_iter()
                .filter(|inode| inet_inodes.contains(inode))
                .collect();
            assert!(
                leaked.is_empty(),
                "the helper (pid {pid}) must hold no network descriptor after the split, but \
                 its fd table still names network socket inode(s) {leaked:?}"
            );
        },
    );
}

/// The worker's own identity -- the thing Fix Round 1 found nothing here
/// actually checked. `start_daemon` passes `--worker-user nobody` (an
/// account that exists on essentially every Unix, unlike the daemon's own
/// default `qshd`, which needs a machine set up for it).
///
/// This test says nothing about the parent-death signal; see
/// `the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open`
/// below for that, kept deliberately separate (one variable per test).
///
/// Needs root, and `/proc/<pid>/task/<pid>/children` (see
/// `wait_for_worker_pid`'s docs) to find the worker's pid at all --
/// skipped, loudly, when either is unavailable.
#[test]
fn the_worker_holds_no_privileged_log_descriptor_after_the_split() {
    use std::os::unix::fs::MetadataExt;

    const NAME: &str = "the_worker_holds_no_privileged_log_descriptor_after_the_split";
    common::on_a_disposable_host(NAME, WHAT_THESE_TESTS_DO, || {
        common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
        let dir = tempfile::tempdir().expect("tempdir");
        let (daemon, _, _) = common::start_daemon(dir.path());
        let helper_pid = daemon.child.id();
        let worker_pid = wait_for_worker_pid(helper_pid)
            .expect("the disposable Linux fixture exposes the helper's children");
        let nobody = nix::unistd::User::from_name("nobody")
            .unwrap()
            .expect("fixture worker account");
        wait_until_worker_is_armed_the_second_time(worker_pid, nobody.uid);

        let log = std::fs::metadata(common::daemon_log_path()).expect("helper log exists");
        assert_eq!(log.uid(), 0, "the fixture log must belong to the helper");
        let same_file_fds = |pid: u32| -> Vec<i32> {
            std::fs::read_dir(format!("/proc/{pid}/fd"))
                .expect("inspect owned fixture process descriptors")
                .map(|entry| entry.expect("descriptor entry"))
                .filter_map(|entry| {
                    let metadata = match std::fs::metadata(entry.path()) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
                        Err(error) => panic!("cannot inspect fixture descriptor: {error}"),
                    };
                    (metadata.dev() == log.dev() && metadata.ino() == log.ino())
                        .then(|| entry.file_name().to_string_lossy().parse().unwrap())
                })
                .collect()
        };
        assert!(!same_file_fds(helper_pid).is_empty(), "helper owns the log");
        assert!(
            same_file_fds(worker_pid).is_empty(),
            "the worker must not retain authority over the privileged log inode"
        );
    });
}

#[test]
fn the_worker_runs_as_its_configured_account() {
    common::on_a_disposable_host(
        "the_worker_runs_as_its_configured_account",
        WHAT_THESE_TESTS_DO,
        || {
            // See `the_helper_holds_no_network_descriptor_after_the_split`:
            // since Task 2, the daemon needs its own PAM service file to
            // start at all.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let dir = tempfile::tempdir().expect("tempdir");
            let (mut daemon, _server_pub, _port) = common::start_daemon(dir.path());
            let helper_pid = daemon.child.id();

            let Some(worker_pid) = wait_for_worker_pid(helper_pid) else {
                eprintln!(
                    "SKIPPED the_worker_runs_as_its_configured_account: this kernel does not \
                     expose /proc/<pid>/task/<pid>/children (needs CONFIG_PROC_CHILDREN), so \
                     the worker's pid cannot be found from here."
                );
                let _ = daemon.child.kill();
                let _ = daemon.child.wait();
                return;
            };

            let nobody = nix::unistd::User::from_name("nobody")
                .expect("read the nobody account's passwd entry")
                .expect(
                    "the nobody account exists on this machine -- start_daemon always asks for \
                     it",
                );

            // Bounded, not a single immediate read: right after the fork
            // the worker is still root for however long
            // `drop_worker_privileges` takes.
            let (uids, gids, groups) = wait_for_worker_uid(worker_pid, nobody.uid);
            assert!(
                gids.iter().all(|&g| g == nobody.gid.as_raw()),
                "the worker's real/effective/saved/fs gid must all be nobody's ({}), got \
                 {gids:?}",
                nobody.gid
            );
            let mut actual_groups = groups.clone();
            actual_groups.sort_unstable();
            let expected = expected_groups("nobody", nobody.gid);
            assert_eq!(
                actual_groups, expected,
                "the worker's supplementary groups must match nobody's own getgrouplist result \
                 exactly, not merely contain its primary group; uids observed were {uids:?}"
            );

            let _ = daemon.child.kill();
            let _ = daemon.child.wait();
        },
    );
}

/// Fix Round 1's version of this test did not actually isolate anything:
/// `SIGKILL`ing the helper closes every descriptor it held, including its
/// end of the seam, and the worker's OWN reader thread already ends the
/// process on that alone (wired in `spawner::worker_clients`)
/// -- so that test passed identically with the parent-death-signal re-arm
/// deleted, and even with the original (Critical-bug) arm-before-the-drop-
/// only order.
///
/// Fix Round 2's version isolated the signal for real (via `pidfd_getfd`,
/// see below) but killed the helper as soon as the worker's PID appeared,
/// before the worker had necessarily dropped privileges at all -- so a
/// kill landing before the SECOND `arm_and_verify_pdeathsig` call would be
/// caught by the FIRST arming instead, and the "second arming deleted"
/// regression would still pass. `wait_until_worker_is_armed_the_second_time`
/// below closes that: PROVEN, not merely probably-long-enough-waited,
/// progress past the exact call this test exists to exercise.
///
/// Every one of these was run for real as a control before landing; see
/// the fix round reports for their output.
///
/// To isolate the signal itself, THIS test keeps its own references to the
/// helper's ends of both seams alive -- via `pidfd_open`+`pidfd_getfd`
/// (Linux 5.6+), duplicated into this test process BEFORE the helper dies
/// -- so nothing on the worker's side sees end-of-file when the helper is
/// killed: neither the reader thread on the channel seam nor the one on the
/// authentication seam, either of which would end the process itself. This
/// is exactly the situation a later slice's PAM monitor, forked between the
/// helper's fork and its exec, would create for real if it held the
/// helper's seams open past the helper's own death. With the sockets held open from outside, only the
/// parent-death signal can end the worker.
///
/// Needs root and `/proc/<pid>/task/<pid>/children` (see
/// `wait_for_worker_pid`'s docs) -- skipped, loudly, when either is
/// unavailable. A kernel old enough to lack `pidfd_open`/`pidfd_getfd`
/// entirely (`ENOSYS`) is ALSO a skip -- anything else those two return
/// (`EPERM` from Yama's `ptrace_scope=3` or a seccomp profile among them:
/// `pidfd_getfd` needs the same access `ptrace(2)` would by default) is a
/// different fact than "too old a kernel" and is a hard panic instead, per
/// `is_enosys`'s docs.
#[test]
fn the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open() {
    common::on_a_disposable_host(
        "the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open",
        WHAT_THESE_TESTS_DO,
        || {
            // See `the_helper_holds_no_network_descriptor_after_the_split`:
            // since Task 2, the daemon needs its own PAM service file to
            // start at all.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let dir = tempfile::tempdir().expect("tempdir");
            let (mut daemon, _server_pub, _port) = common::start_daemon(dir.path());
            let helper_pid = daemon.child.id();

            let nobody = nix::unistd::User::from_name("nobody")
                .expect("read the nobody account's passwd entry")
                .expect(
                    "the nobody account exists on this machine -- start_daemon always asks for \
                     it",
                );

            let Some(worker_pid) = wait_for_worker_pid(helper_pid) else {
                eprintln!(
                    "SKIPPED the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open: \
                     this kernel does not expose /proc/<pid>/task/<pid>/children (needs \
                     CONFIG_PROC_CHILDREN), so the worker's pid cannot be found from here."
                );
                let _ = daemon.child.kill();
                let _ = daemon.child.wait();
                return;
            };

            // Grabbed immediately, before anything else touches the
            // worker: a `pidfd` pins THIS process instance, immune to the
            // pid being reaped by `init` and reused for an unrelated
            // process by the time the cleanup guard below runs -- which a
            // bare `kill(worker_pid, ...)` would not be. `ENOSYS` here
            // means this whole approach cannot work on this kernel at all
            // (older than pidfd_open itself, Linux 5.3) and is the one
            // legitimate skip; anything else is a hard failure, not a
            // "maybe unsupported" -- see `is_enosys`'s docs.
            let worker_pidfd = match pidfd_open(worker_pid) {
                Ok(fd) => fd,
                Err(e) if is_enosys(&e) => {
                    eprintln!(
                        "SKIPPED \
                         the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open: \
                         pidfd_open is not implemented on this kernel (ENOSYS)."
                    );
                    let _ = daemon.child.kill();
                    let _ = daemon.child.wait();
                    return;
                }
                Err(e) => panic!("pidfd_open({worker_pid}) (the worker) failed: {e}"),
            };

            // A safety net, not the assertion: if this test's own logic is
            // wrong and the worker survives, it would otherwise leak as a
            // permanent orphan -- its real parent is about to be killed,
            // and if it does not die on its own there is nothing left to
            // reap it. This makes sure it is gone by the time this
            // function returns, panic or not, signalling through the
            // pinned `pidfd` above rather than a bare pid.
            struct KillWorkerOnDrop(OwnedFd);
            impl Drop for KillWorkerOnDrop {
                fn drop(&mut self) {
                    let _ = pidfd_send_signal(self.0.as_fd(), nix::sys::signal::Signal::SIGKILL);
                }
            }
            let _reap_worker = KillWorkerOnDrop(worker_pidfd);

            // Must not kill the helper before this returns: see this
            // test's own docs (Fix Round 2's version raced exactly this).
            wait_until_worker_is_armed_the_second_time(worker_pid, nobody.uid);

            let seam_fds = seam_fd_numbers(helper_pid);
            let helper_pidfd = match pidfd_open(helper_pid) {
                Ok(fd) => fd,
                Err(e) if is_enosys(&e) => {
                    eprintln!(
                        "SKIPPED \
                         the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open: \
                         pidfd_open is not implemented on this kernel (ENOSYS)."
                    );
                    let _ = daemon.child.kill();
                    let _ = daemon.child.wait();
                    return;
                }
                Err(e) => panic!("pidfd_open({helper_pid}) (the helper) failed: {e}"),
            };
            let mut held_open = Vec::new();
            for seam_fd in seam_fds {
                match pidfd_getfd(helper_pidfd.as_fd(), seam_fd) {
                    Ok(fd) => held_open.push(fd),
                    Err(e) if is_enosys(&e) => {
                        eprintln!(
                            "SKIPPED \
                             the_worker_dies_when_the_helper_dies_even_with_the_seam_held_open: \
                             pidfd_getfd is not implemented on this kernel (ENOSYS, needs Linux \
                             5.6+)."
                        );
                        let _ = daemon.child.kill();
                        let _ = daemon.child.wait();
                        return;
                    }
                    Err(e) => panic!(
                        "pidfd_getfd(helper={helper_pid}, fd={seam_fd}) failed: {e} -- if this \
                         is EPERM, Yama's ptrace_scope or a seccomp profile is refusing \
                         pidfd_getfd the same access ptrace(2) would need by default, which is \
                         a real restriction this test cannot work around, not an unsupported \
                         kernel"
                    ),
                }
            }

            // The duplicates must be the seams themselves, not merely SOME
            // sockets that happened to be the only ones found:
            // `seam_fd_numbers` already narrows to exactly three AF_UNIX
            // candidates, and this confirms each one's type matches
            // `helper::channel::pair`'s `SOCK_SEQPACKET` exactly.
            for fd in &held_open {
                let sock_type =
                    nix::sys::socket::getsockopt(fd, nix::sys::socket::sockopt::SockType)
                        .expect("getsockopt(SO_TYPE) on a duplicated seam descriptor");
                assert_eq!(
                    sock_type,
                    nix::sys::socket::SockType::SeqPacket,
                    "every descriptor pidfd_getfd duplicated must be a SOCK_SEQPACKET seam, got \
                     {sock_type:?}"
                );
            }

            // The point of the whole setup: kill the helper outright,
            // while THIS process still holds live references to its ends
            // of both seams -- the worker's side will never see
            // end-of-file on either, so ONLY the parent-death signal can
            // end it now.
            daemon.child.kill().expect("SIGKILL the helper");

            let deadline = Instant::now() + WORKER_WAIT;
            let worker_gone = loop {
                if !Path::new(&format!("/proc/{worker_pid}")).exists() {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(20));
            };

            // Kept alive explicitly through the whole wait above --
            // dropped only now, so they cannot be optimised or reordered
            // away from under the assertion they exist to make true.
            drop(held_open);

            assert!(
                worker_gone,
                "the worker (pid {worker_pid}) must exit once the helper (pid {helper_pid}) is \
                 killed, through the parent-death signal, even with this test's own references \
                 to both seam sockets keeping them from ever seeing end-of-file -- it is still \
                 there after {WORKER_WAIT:?}"
            );

            let _ = daemon.child.wait();
        },
    );
}

/// Every LIVE process `/proc` says is a child of `pid` -- a zombie is a
/// child the kernel still lists and nothing at all to look at, so it is
/// left out here.
///
/// The whole scan tolerates a process disappearing under it: a candidate
/// that is reaped between `read_dir` naming it and this reading its
/// `status` simply drops out (`.ok()?`), which is right -- it is no longer
/// anyone's child. Only the `read_dir` of `/proc` itself must succeed.
///
/// Scanned out of `/proc/*/status` rather than read from
/// `/proc/<pid>/task/<pid>/children`, which needs a kernel option
/// (`CONFIG_PROC_CHILDREN`) the test below would otherwise have to skip
/// around -- and it is exactly the test that must not be skipped on a
/// kernel that can run the daemon perfectly well.
fn children_of(pid: u32) -> Vec<u32> {
    // `PPid:` and `State:` out of one read, so the two cannot describe two
    // different moments of the same process.
    let parent_and_state = |candidate: u32| -> Option<(u32, String)> {
        let status = std::fs::read_to_string(format!("/proc/{candidate}/status")).ok()?;
        let field = |prefix: &str| -> Option<String> {
            Some(
                status
                    .lines()
                    .find(|line| line.starts_with(prefix))?
                    .trim_start_matches(prefix)
                    .trim()
                    .to_string(),
            )
        };
        Some((field("PPid:")?.parse().ok()?, field("State:")?))
    };
    std::fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|candidate| {
            parent_and_state(*candidate)
                .is_some_and(|(parent, state)| parent == pid && !state.starts_with('Z'))
        })
        .collect()
}

/// A login's monitor holds NO seam of the helper's, and the worker sees the
/// end of its own when the helper dies.
///
/// A monitor is forked from the helper and never execs, so close-on-exec
/// closes nothing for it: every descriptor the helper had at that moment --
/// both seams to the worker, the master side of every channel that was
/// starting, and one socket per monitor already alive -- is the monitor's
/// to close, or it keeps them open. What that costs is the property this
/// test's second half watches: a worker whose helper has died sees
/// end-of-file on its seam ONLY because nothing else holds the helper's end
/// of it, and a monitor that kept a copy would leave that worker reading a
/// socket whose peer is a corpse.
///
/// Driven against a real `qshd serve --system`, with a real client logged
/// in and a real channel open, because a monitor exists only once a channel
/// has been asked for: this is the one place the descriptor table of a real
/// one can be looked at from outside.
///
/// Needs root, like everything else in this file.
#[test]
fn a_monitor_holds_no_seam_and_the_worker_still_sees_the_end() {
    const NAME: &str = "a_monitor_holds_no_seam_and_the_worker_still_sees_the_end";
    common::on_a_disposable_host(NAME, WHAT_THESE_TESTS_DO, || {
        // See `the_helper_holds_no_network_descriptor_after_the_split`:
        // since Task 2, the daemon needs its own PAM service file to start
        // at all.
        common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("keygen");
        common::write_authorized_keys(dir.path(), &key);
        let (mut daemon, server_pub, port) = common::start_daemon(dir.path());
        let helper_pid = daemon.child.id();

        let Some(worker_pid) = wait_for_worker_pid(helper_pid) else {
            eprintln!(
                "SKIPPED {NAME}: this kernel does not expose /proc/<pid>/task/<pid>/children \
                 (needs CONFIG_PROC_CHILDREN), so the worker's pid cannot be found from here."
            );
            let _ = daemon.child.kill();
            let _ = daemon.child.wait();
            return;
        };

        // A real login with a real channel: the monitor exists from the
        // first `Open` of a login and not before. The session is held for
        // the whole of the first half, so the channel -- and the monitor
        // behind it -- stay alive while its descriptors are read.
        let session = common::Session::connect(port, server_pub, &key, &common::current_login());
        session.open_shell();

        // The helper's live children are the worker and the monitors -- but
        // not ONLY those, and not only while a login is being set up: the
        // helper also forks a short-lived process to read this account's
        // `authorized_keys` as the account (`helper::authorized`) and
        // another to verify the proof (`helper/server.rs`), and either can
        // still be on its way out when this first looks. That is a state
        // to WAIT THROUGH, not to fail on: this loop used to panic the
        // moment it saw a second pid, and under load that is a third of
        // runs. So it waits for the picture to settle to exactly one
        // non-worker child, and only the deadline fails -- naming what it
        // saw, which a bare "never forked a monitor" did not.
        //
        // The worker must still be among the helper's children each time
        // round, or the pid this filters by is stale and "everything else"
        // would silently include the real worker.
        let deadline = Instant::now() + WORKER_WAIT;
        let monitor = loop {
            let children = children_of(helper_pid);
            let worker_still_there = children.contains(&worker_pid);
            let others: Vec<u32> = children
                .iter()
                .copied()
                .filter(|pid| *pid != worker_pid)
                .collect();
            if worker_still_there {
                if let [only] = others[..] {
                    break only;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the helper (pid {helper_pid}) never settled on exactly one live child besides \
                 its worker (pid {worker_pid}) -- the login's monitor -- within {WORKER_WAIT:?}; \
                 last seen children {children:?}, of which the worker was {}",
                if worker_still_there {
                    "one"
                } else {
                    "NOT one, so the worker died or was never this pid"
                }
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        // The monitor's socket table must share nothing with the helper's
        // or the worker's. A COUNT of sockets used to say this, and cannot
        // any more: since the login's PAM session moved into the monitor
        // (`helper::monitor::Session`), Linux-PAM opens sockets of its own
        // in there -- its logging, and whatever a module opens -- and a
        // count cannot tell one of those from a socket of the helper's
        // left behind. The inodes can: two processes naming one socket
        // inode hold the SAME open file, which is exactly what the
        // monitor's descriptor sweep exists to make impossible, and two
        // different sockets never share one.
        let sockets = open_socket_inodes(monitor);
        assert!(
            !sockets.is_empty(),
            "a monitor (pid {monitor}) must still hold its own seam to the helper"
        );
        for (whose, pid) in [("helper", helper_pid), ("worker", worker_pid)] {
            let theirs: HashSet<u64> = open_socket_inodes(pid).into_iter().collect();
            let shared: Vec<u64> = sockets
                .iter()
                .copied()
                .filter(|inode| theirs.contains(inode))
                .collect();
            assert!(
                shared.is_empty(),
                "a monitor must hold no socket of the {whose}'s -- either seam, another \
                 monitor's, or a channel's -- and since it never execs nothing will ever close \
                 it for it; pid {monitor} shares inode(s) {shared:?} with pid {pid}"
            );
        }
        // And no network descriptor, for the same reason the helper holds
        // none: it is a root process, forked from one that had already
        // dropped every such descriptor.
        let inet = inet_socket_inodes(monitor);
        let leaked: Vec<u64> = sockets
            .iter()
            .copied()
            .filter(|inode| inet.contains(inode))
            .collect();
        assert!(
            leaked.is_empty(),
            "a monitor must hold no network descriptor, but pid {monitor} names socket inode(s) \
             {leaked:?}"
        );

        // The second half: the helper dies with a monitor alive, and the
        // worker must be gone inside the bound rather than left reading a
        // seam whose other end a monitor is holding open. Both of the
        // worker's own ways out are honest answers here -- its reader
        // threads see end-of-file, and the parent-death signal fires --
        // and a monitor holding the helper's end of the channel seam
        // would have taken the first of them away.
        daemon.child.kill().expect("SIGKILL the helper");
        let deadline = Instant::now() + WORKER_WAIT;
        while Path::new(&format!("/proc/{worker_pid}")).exists() {
            assert!(
                Instant::now() < deadline,
                "the worker (pid {worker_pid}) must be gone once the helper is killed; it is \
                 still there after {WORKER_WAIT:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // And the monitor goes too: its seam closed with the helper, and a
        // monitor whose helper is gone has nobody left to serve.
        let deadline = Instant::now() + WORKER_WAIT;
        while Path::new(&format!("/proc/{monitor}")).exists() {
            assert!(
                Instant::now() < deadline,
                "the monitor (pid {monitor}) must end once its seam closes with the helper; it \
                 is still there after {WORKER_WAIT:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        drop(session);
        let _ = daemon.child.wait();
    });
}

/// Whether `pid`'s thread list has a thread named `name` yet.
///
/// Refuses, loudly, a name longer than Linux keeps: the kernel cuts a
/// thread's name to `MAX_THREAD_NAME_LEN` bytes, so such a name can never
/// match, and a caller waiting for it would only time out -- reporting a
/// thread that "never started" when it had started under a shorter name.
fn has_thread_named(pid: u32, name: &str) -> bool {
    assert!(
        name.len() <= MAX_THREAD_NAME_LEN,
        "{name:?} is {} bytes, longer than the {MAX_THREAD_NAME_LEN} bytes Linux keeps of a \
         thread's name: no thread can ever be found under it",
        name.len()
    );
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|tasks| {
            tasks.filter_map(|t| t.ok()).any(|t| {
                std::fs::read_to_string(t.path().join("comm"))
                    .map(|comm| comm.trim_end() == name)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Field `field` (1-based, as `proc(5)` numbers them) of
/// `/proc/<pid>/stat`, counted after the parenthesised `comm`.
fn proc_stat_field(pid: u32, field: usize) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 2..];
    // Field 3 (`state`) is the first one after `comm`.
    after_comm
        .split_whitespace()
        .nth(field - 3)
        .map(str::to_string)
}

/// The worker's authentication-seam reader ends the worker on its own,
/// with nothing else able to: the helper is frozen (`SIGSTOP`), so it is
/// alive -- no parent-death signal -- and its end of the channel seam stays
/// open, and only the authentication seam is shut down, through a
/// duplicate of the helper's end taken with `pidfd_getfd`. The worker must
/// then exit with status 1 (`end_the_worker`), not be killed.
///
/// Which of the helper's two seam descriptors is the authentication one:
/// `split_and_run` makes the channel pair first and the authentication pair
/// right after it, with nothing closed in between, and a new descriptor
/// always takes the lowest free number -- so both of the authentication
/// pair's descriptors are numbered above both of the channel pair's, and the
/// helper's authentication end is the middle of its three (diagnostics is last). Socket inode
/// numbers are no second witness: the kernel hands them out from per-CPU
/// batches, so a process that moves to another CPU between the two
/// `socketpair` calls can get the later pair a LOWER inode. What does
/// confirm it is the worker's own log, afterwards: only the authentication
/// seam's reader writes `AUTH_SEAM_CLOSED_LOG`, so finding that line proves
/// the seam shut down was that one, and that its reader is what noticed.
///
/// The worker, once it exits, stays a zombie of the frozen helper, so
/// `/proc/<pid>` does not go away: its state (`Z`) and exit code (field
/// 52, as `waitpid` would report it) are what is read.
#[test]
fn the_worker_ends_itself_when_only_its_authentication_seam_is_lost() {
    const NAME: &str = "the_worker_ends_itself_when_only_its_authentication_seam_is_lost";
    common::on_a_disposable_host(NAME, WHAT_THESE_TESTS_DO, || {
        // See `the_helper_holds_no_network_descriptor_after_the_split`:
        // since Task 2, the daemon needs its own PAM service file to start
        // at all.
        common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut daemon, _server_pub, _port) = common::start_daemon(dir.path());
        let helper_pid = daemon.child.id();
        let Some(worker_pid) = wait_for_worker_pid(helper_pid) else {
            eprintln!("SKIPPED {NAME}: no /proc/<pid>/task/<pid>/children on this kernel.");
            return;
        };
        let worker_pidfd = match pidfd_open(worker_pid) {
            Ok(fd) => fd,
            Err(e) if is_enosys(&e) => {
                eprintln!("SKIPPED {NAME}: pidfd_open is not implemented on this kernel.");
                return;
            }
            Err(e) => panic!("pidfd_open({worker_pid}) (the worker) failed: {e}"),
        };
        struct KillOnDrop(u32);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                // SIGKILL ends a stopped process too; the worker goes with
                // its parent through the parent-death signal.
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(self.0 as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _kill_helper = KillOnDrop(helper_pid);

        // The authentication client exists: its reader thread is named.
        let deadline = Instant::now() + WORKER_WAIT;
        while !has_thread_named(worker_pid, AUTH_READER_THREAD) {
            assert!(
                Instant::now() < deadline,
                "the worker (pid {worker_pid}) never started its authentication seam's reader"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        // The second of three ordered descriptors: channel, authentication,
        // test's docs for why that is the authentication seam, and for
        // what confirms it once the worker has ended.
        let mut seams = seam_fd_numbers(helper_pid);
        seams.sort_unstable();
        let auth_fd = seams[1];
        let helper_pidfd = match pidfd_open(helper_pid) {
            Ok(fd) => fd,
            Err(e) if is_enosys(&e) => {
                eprintln!("SKIPPED {NAME}: pidfd_open is not implemented on this kernel.");
                return;
            }
            Err(e) => panic!("pidfd_open({helper_pid}) (the helper) failed: {e}"),
        };
        let auth_seam = match pidfd_getfd(helper_pidfd.as_fd(), auth_fd) {
            Ok(fd) => fd,
            Err(e) if is_enosys(&e) => {
                eprintln!("SKIPPED {NAME}: pidfd_getfd is not implemented on this kernel.");
                return;
            }
            Err(e) => panic!("pidfd_getfd(helper={helper_pid}, fd={auth_fd}) failed: {e}"),
        };

        // Freeze the helper, and wait until it really is stopped.
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(helper_pid as i32),
            nix::sys::signal::Signal::SIGSTOP,
        )
        .expect("SIGSTOP the helper");
        let deadline = Instant::now() + WORKER_WAIT;
        while proc_stat_field(helper_pid, 3).as_deref() != Some("T") {
            assert!(Instant::now() < deadline, "the helper never stopped");
            std::thread::sleep(Duration::from_millis(5));
        }

        // Lose only the authentication seam.
        nix::sys::socket::shutdown(auth_seam.as_raw_fd(), nix::sys::socket::Shutdown::Both)
            .expect("shut the authentication seam down");

        let mut fds = [nix::poll::PollFd::new(
            worker_pidfd.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        let ended = nix::poll::poll(
            &mut fds,
            nix::poll::PollTimeout::try_from(WORKER_WAIT).expect("a poll timeout"),
        )
        .expect("poll the worker's pidfd")
            == 1;
        let helper_state = proc_stat_field(helper_pid, 3);
        let worker_state = proc_stat_field(worker_pid, 3);
        let exit_code = proc_stat_field(worker_pid, 52);
        drop(auth_seam);

        assert_eq!(
            helper_state.as_deref(),
            Some("T"),
            "the helper must still be alive and stopped, or something else could have ended \
             the worker"
        );
        assert!(
            ended,
            "the worker (pid {worker_pid}) must end itself once its authentication seam is \
             lost -- it is still running {WORKER_WAIT:?} later (state {worker_state:?})"
        );
        assert_eq!(
            (worker_state.as_deref(), exit_code.as_deref()),
            (Some("Z"), Some("256")),
            "the worker must have exited with status 1 (end_the_worker), not been killed"
        );
        // The seam that was shut down was the authentication one, and its
        // reader is what noticed: had the channel seam been taken for it,
        // the channel seam's reader would have ended the worker instead,
        // and this line would be missing.
        let deadline = Instant::now() + WORKER_WAIT;
        let log = loop {
            let log = daemon.stderr_text();
            if log.contains(AUTH_SEAM_CLOSED_LOG) || Instant::now() >= deadline {
                break log;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(
            log.contains(AUTH_SEAM_CLOSED_LOG),
            "the worker stderr must identify the lost authentication seam ({AUTH_SEAM_CLOSED_LOG:?}) \
             while the helper is stopped; captured stderr: {log}"
        );

        let _ = daemon.child.kill();
        let _ = daemon.child.wait();
    });
}

/// `has_thread_named` refuses a name Linux could never report, rather than
/// letting its caller wait for a thread that will never be found. Needs no
/// root and no daemon: the refusal comes before any look at `/proc`.
#[test]
fn a_thread_name_linux_would_cut_is_refused_at_once() {
    let too_long = "x".repeat(MAX_THREAD_NAME_LEN + 1);
    let refused = std::panic::catch_unwind(|| has_thread_named(std::process::id(), &too_long));
    let why = match refused {
        Ok(found) => panic!(
            "a {}-byte thread name must be refused, not looked for (found: {found})",
            too_long.len()
        ),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    };
    assert!(
        why.contains("bytes Linux keeps"),
        "the refusal must name the limit, got: {why:?}"
    );
    // And a name at the limit is looked for as usual.
    let at_limit = "x".repeat(MAX_THREAD_NAME_LEN);
    assert!(
        !has_thread_named(std::process::id(), &at_limit),
        "no thread of this test is named {at_limit:?}"
    );
}
