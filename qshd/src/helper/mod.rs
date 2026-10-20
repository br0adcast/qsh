//! The privileged helper and the seam between it and the worker.
//!
//! `qshd serve --system` splits in two before the tokio runtime exists: the
//! parent becomes a single-threaded helper that owns pseudo-terminals and
//! decides who has authenticated, the child becomes the worker that owns the
//! network. They talk over two `socketpair`s created before the fork: the
//! channel seam, over which channel file descriptors travel back with
//! `SCM_RIGHTS`, and the authentication seam, over which the worker asks for
//! handshake nonces and for the helper's verdict on each client's proof
//! (see `protocol`'s docs for what rides where).
//!
//! The worker drops root for its own configured account right after the
//! fork (`drop_worker_privileges`), before it ever touches the network --
//! opening a PAM session for the account it serves on each channel is a
//! later task's job, not this one's.
//!
//! Both ends of each socketpair are always the same binary image -- they
//! are one `fork` apart -- so the protocol below needs no version
//! negotiation and never will.

pub mod account;
pub mod authorized;
pub mod channel;
pub mod config;
/// The per-login monitor: the process the helper forks between itself and a
/// login's shells, and where the PAM session will live. Private to
/// `helper` -- nothing outside it forks one or speaks to one.
mod monitor;
/// Linux-PAM, spoken directly: hand-written declarations, the conversation
/// function, thin wrappers. Its caller is the per-login monitor, which
/// opens and closes each login's session (`monitor::Session`); nothing
/// else speaks PAM, and nothing outside `helper` reaches this module at
/// all. Until that caller existed the module was dead outside its own
/// tests and carried `#[cfg_attr(not(test), allow(dead_code))]`; the
/// allowance went with the caller's arrival, as it was promised it would.
mod pam;
/// The helper's waiting room: requests whose child has not spoken yet.
/// Private to `helper` -- nothing outside it has any business holding one.
mod pending;
pub mod protocol;
#[cfg(target_os = "linux")]
mod scope_ops;
pub mod server;
#[cfg(target_os = "linux")]
mod shell_owner;
pub mod spawner;
#[cfg(target_os = "linux")]
mod startup;

use anyhow::Context;

pub use config::HelperConfig;

/// Whether `account` carries any trace of root: as its own uid, its own
/// primary group, or among its supplementary groups. Any one of the three
/// would let the worker keep (or regain, through that group) privilege
/// `drop_worker_privileges`'s later id/group verification cannot see,
/// because that verification only checks that the account's OWN
/// ids/groups took -- it says nothing about whether those ids/groups were
/// themselves privileged to begin with.
fn account_is_privileged(account: &account::Account) -> bool {
    account.uid.is_root()
        || account.gid.as_raw() == 0
        || account.groups.iter().any(|g| g.as_raw() == 0)
}

/// Refuse to run the system mode with a securebit set that would let a
/// channel's process keep root's capabilities across its `setuid` to the
/// account.
///
/// `SECBIT_NO_SETUID_FIXUP` stops the kernel clearing the capability sets on
/// a uid transition away from root; `SECBIT_KEEP_CAPS` does the same for one
/// `setuid` (and `execve` clears it, so it should never arrive here from a
/// service manager -- checked anyway, cheaply). Under either, the drop in
/// `helper::monitor::fork_shell` would leave the account's program holding
/// `CAP_DAC_*` and, with an ambient set, keep capabilities into its own
/// code. The child's own capability check (`server`'s
/// `check_no_capabilities`, module-private) catches this per channel, but
/// refusing to start at all -- with a message the operator can act on --
/// beats every login failing mysteriously.
///
/// Called once, at startup, before the split.
pub fn refuse_dangerous_securebits() -> anyhow::Result<()> {
    // SAFETY: `PR_GET_SECUREBITS` takes no arguments and returns the bits or
    // -1; it touches nothing this process owns.
    let bits = unsafe { nix::libc::prctl(nix::libc::PR_GET_SECUREBITS) };
    if bits < 0 {
        anyhow::bail!(
            "reading this process's securebits (prctl PR_GET_SECUREBITS) failed: {}",
            nix::errno::Errno::last()
        );
    }
    let dangerous = nix::libc::SECBIT_NO_SETUID_FIXUP | nix::libc::SECBIT_KEEP_CAPS;
    if bits & dangerous != 0 {
        anyhow::bail!(
            "the system mode refuses to start with SECBIT_NO_SETUID_FIXUP or SECBIT_KEEP_CAPS \
             set (securebits {bits:#x}): a channel's process would keep root's capabilities \
             across the drop to its account. Remove SecureBits= from the service unit"
        );
    }
    Ok(())
}

/// Drop the worker to its own unprivileged account, for good.
///
/// Order matters and is not interchangeable: supplementary groups and the
/// group id have to go first, because after the user id moves the process
/// can no longer change either -- it would keep whatever groups the
/// privileged parent had. The user id moves last and is meant to be
/// irreversible (the real, effective AND saved ids all move to the same
/// unprivileged account, via `setresuid` rather than `setuid` -- see the
/// verification below for why that distinction matters), which is the
/// point: the half that parses everything a stranger sends must not be
/// able to return.
pub fn drop_worker_privileges(user: &str) -> anyhow::Result<()> {
    let account =
        account::lookup(user).with_context(|| format!("looking up the worker account {user}"))?;
    // `root`, or any account aliased to uid/gid 0 anywhere -- its own uid,
    // its own primary group, or among its supplementary groups -- would
    // make every check below pass trivially while leaving the worker
    // exactly as privileged as it started. Refuse before a single `set*`
    // call rather than discover it in the verification.
    if account_is_privileged(&account) {
        anyhow::bail!(
            "the worker account {user} carries root privilege (uid {}, gid {}, supplementary \
             groups {:?}) -- refusing to run the network-facing worker as root or root's group",
            account.uid,
            account.gid,
            account.groups
        );
    }

    nix::unistd::setgroups(&account.groups).context("setting the worker's groups")?;
    // `setresgid`/`setresuid`, not `setgid`/`setuid`: the plain calls only
    // guarantee the EFFECTIVE id moves when starting from root (the real
    // and saved ids follow as a side effect of the same rule, but that is
    // an implementation detail this function should not lean on when it is
    // about to prove the move happened on all three explicitly, one line
    // down). Setting all three at once, by name, is what makes that proof
    // meaningful instead of circular.
    nix::unistd::setresgid(account.gid, account.gid, account.gid)
        .context("setting the worker's real, effective and saved group id")?;
    nix::unistd::setresuid(account.uid, account.uid, account.uid)
        .context("setting the worker's real, effective and saved user id")?;

    // A failed drop that returned Ok would leave the network half running
    // as root. Prove it took, on every axis that matters, not just the
    // effective id `Uid::effective()` alone would show:
    let res_uid = nix::unistd::getresuid().context("reading back the worker's user ids")?;
    let res_gid = nix::unistd::getresgid().context("reading back the worker's group ids")?;
    if res_uid.real != account.uid
        || res_uid.effective != account.uid
        || res_uid.saved != account.uid
    {
        anyhow::bail!(
            "the worker's user id did not fully move to {} (real {}, effective {}, saved {}) -- \
             refusing to serve",
            account.uid,
            res_uid.real,
            res_uid.effective,
            res_uid.saved
        );
    }
    if res_gid.real != account.gid
        || res_gid.effective != account.gid
        || res_gid.saved != account.gid
    {
        anyhow::bail!(
            "the worker's group id did not fully move to {} (real {}, effective {}, saved {}) -- \
             refusing to serve",
            account.gid,
            res_gid.real,
            res_gid.effective,
            res_gid.saved
        );
    }
    // The supplementary list, too: the kernel sorts it on the way back out
    // of `setgroups`/`getgroups` (by gid, for its own lookup purposes), so
    // this compares the two as multisets, not as ordered lists.
    let mut expected: Vec<u32> = account.groups.iter().map(|g| g.as_raw()).collect();
    expected.sort_unstable();
    let mut actual: Vec<u32> = nix::unistd::getgroups()
        .context("reading back the worker's supplementary groups")?
        .iter()
        .map(|g| g.as_raw())
        .collect();
    actual.sort_unstable();
    if actual != expected {
        anyhow::bail!(
            "the worker's supplementary groups did not take (expected {expected:?}, got \
             {actual:?}) -- refusing to serve"
        );
    }
    // The id checks above prove every id MOVED; they do not prove root is
    // now UNREACHABLE. Two independent gaps, both closed below:
    //
    // 1. Under `SECBIT_KEEP_CAPS`, a uid transition away from root clears
    //    only the EFFECTIVE capability set unconditionally; the PERMITTED
    //    set survives (the AMBIENT set does not survive -- the kernel
    //    clears it unconditionally on this same transition regardless of
    //    `KEEP_CAPS`, so checking it below is a harmless, non-load-bearing
    //    belt-and-suspenders, not what actually closes this gap). A bare
    //    `setuid(0)` probe is blind to the permitted-set survival: it
    //    correctly fails right now, with nothing raised into the effective
    //    set to make it succeed, but a later `capset` could still raise a
    //    surviving permitted capability (`CAP_SETUID` among them) into the
    //    effective set and succeed where this probe just failed. So the
    //    probe alone proves only "not reachable in one step right now,"
    //    never "unreachable" -- which is what an EARLIER version of this
    //    function's comment incorrectly claimed for it. Checking that the
    //    permitted set is actually EMPTY is what closes this: with nothing
    //    permitted, no later `capset` has anything left to raise.
    //    What actually keeps this unreachable TODAY: `execve` unconditionally
    //    clears `SECBIT_KEEP_CAPS` -- documented behaviour of that specific
    //    bit, unlike most other securebits -- so nothing a service manager
    //    sets before exec'ing this binary (a systemd unit's `SecureBits=`
    //    included) can arrive here still set. Only `qshd`'s OWN code,
    //    calling `prctl(PR_SET_KEEPCAPS, 1)` on itself AFTER that exec,
    //    could set it, and nothing here does. That is a fact about this
    //    codebase today, not a property the kernel enforces -- which is
    //    exactly why this is checked at all rather than merely asserted in
    //    a comment.
    // 2. The probe itself, kept as a second, independent proof rather than
    //    replaced: an actual `setuid(0)` attempt must FAIL -- the same
    //    pattern OpenSSH's `permanently_set_uid` uses.
    let caps = own_capability_sets().context("reading back the worker's own capability sets")?;
    if caps.permitted != 0 || caps.effective != 0 || caps.ambient != 0 {
        anyhow::bail!(
            "the worker still holds capabilities after the drop (permitted {:#x}, effective \
             {:#x}, ambient {:#x}) -- a later capset could still raise one of them and regain \
             root even though setuid(0) alone would fail right now; refusing to serve",
            caps.permitted,
            caps.effective,
            caps.ambient
        );
    }
    if nix::unistd::setuid(nix::unistd::ROOT).is_ok() {
        anyhow::bail!(
            "the worker could regain root after the drop (setuid(0) succeeded) -- refusing to \
             serve"
        );
    }
    Ok(())
}

/// This process's own `CapPrm`/`CapEff`/`CapAmb` capability sets, each a
/// 64-bit bitmask, parsed from `/proc/self/status` (format documented in
/// `capabilities(7)`/`proc(5)`) rather than through a `capget(2)` binding
/// -- `nix` 0.28 has none, and a dedicated `caps`-style crate would be a
/// heavier dependency than three lines of one file this process already
/// has open by the time this runs.
struct CapabilitySets {
    permitted: u64,
    effective: u64,
    ambient: u64,
}

fn own_capability_sets() -> anyhow::Result<CapabilitySets> {
    let status = std::fs::read_to_string("/proc/self/status")
        .context("reading this process's own /proc/self/status")?;
    parse_capability_sets(&status)
}

/// The parsing half of [`own_capability_sets`], split out so it can be
/// exercised directly against a hand-built string -- in particular the
/// case a real `/proc/self/status` on this development machine can never
/// produce: a kernel old enough to have no `CapAmb:` line at all.
fn parse_capability_sets(status: &str) -> anyhow::Result<CapabilitySets> {
    let find_line = |prefix: &str| status.lines().find(|line| line.starts_with(prefix));
    let parse_required = |prefix: &str| -> anyhow::Result<u64> {
        let line = find_line(prefix)
            .with_context(|| format!("no {prefix:?} line in /proc/self/status"))?;
        u64::from_str_radix(line.trim_start_matches(prefix).trim(), 16)
            .with_context(|| format!("parsing the {prefix:?} line {line:?}"))
    };
    // Ambient capabilities were added in Linux 4.3; a kernel older than
    // that (a stock RHEL 7's 3.10, for one real example) has no `CapAmb:`
    // line at all. Its absence means no ambient set ever existed on this
    // kernel, not that reading it failed -- treated as zero rather than as
    // an error, so the system mode is not refused outright merely for
    // running on a kernel old enough to predate this one field.
    let ambient = match find_line("CapAmb:") {
        Some(line) => u64::from_str_radix(line.trim_start_matches("CapAmb:").trim(), 16)
            .with_context(|| format!("parsing the \"CapAmb:\" line {line:?}"))?,
        None => 0,
    };
    Ok(CapabilitySets {
        permitted: parse_required("CapPrm:")?,
        effective: parse_required("CapEff:")?,
        ambient,
    })
}

/// Makes sure descriptors 0, 1 and 2 are open, pointing each closed one at
/// `/dev/null`. Called first thing in the system mode, before the process
/// opens anything of its own, and so long before the split.
///
/// Why it matters: the helper opens a pseudo-terminal for every channel,
/// and the kernel hands out the LOWEST free descriptor numbers. Were 0, 1
/// or 2 closed, `openpty` could hand one of them out -- and the channel's
/// child, which `dup2`s the slave onto 0, 1 and 2 and then closes the
/// master, would overwrite that descriptor and then close what it had just
/// set up, starting the account's program with no input or output to speak
/// of. With all three taken, everything the helper opens is 3 or above.
///
/// Rust's own runtime already does the same before `main` on Linux, so
/// today this is a second guarantee rather than the only one -- stated
/// here, where the property is needed, rather than leaning on a runtime
/// detail nothing in this crate controls.
pub fn ensure_standard_descriptors() -> anyhow::Result<()> {
    use nix::fcntl::{fcntl, open, FcntlArg, OFlag};
    use nix::sys::stat::Mode;

    for fd in 0..=2 {
        match fcntl(fd, FcntlArg::F_GETFD) {
            Ok(_) => continue,
            Err(nix::errno::Errno::EBADF) => {}
            Err(e) => anyhow::bail!("checking descriptor {fd}: {e}"),
        }
        // `O_NOCTTY`, as every open in the helper carries -- a session
        // leader must never pick up a controlling terminal by accident --
        // though `/dev/null` is no terminal.
        let null = open("/dev/null", OFlag::O_RDWR | OFlag::O_NOCTTY, Mode::empty())
            .with_context(|| format!("opening /dev/null for descriptor {fd}"))?;
        // The lowest free number: `fd` itself, since everything below it is
        // taken by the time this reaches it. Moved there explicitly all the
        // same, rather than assumed.
        if null != fd {
            nix::unistd::dup2(null, fd)
                .with_context(|| format!("moving /dev/null onto descriptor {fd}"))?;
            let _ = nix::unistd::close(null);
        }
    }
    Ok(())
}

/// Arms `PR_SET_PDEATHSIG(SIGKILL)`, proves the registration took, and
/// proves no death happened in the window since `helper_pid` was last known
/// to be the worker's parent. Called twice by `split_and_run`'s child
/// branch: right after the fork, and again right after
/// `drop_worker_privileges`, because that drop's own uid/gid change clears
/// whatever this armed the first time (`prctl(2)` says so) -- the first
/// call exists so a slow or hung NSS lookup inside the drop does not leave
/// the worker unwatched for however long that takes; the second redoes
/// what the drop just undid.
///
/// `SIGKILL`, not `SIGTERM`: `get_pdeathsig` below can only confirm the
/// setting took, never that delivering it would actually end the process
/// -- see this module's docs for why that distinction matters here, and
/// why `SIGKILL` does not fight an ordinary `systemctl stop`.
///
/// The `getppid` check is what actually closes the race, not the arming
/// call before it: a helper gone at ANY point up to and including this
/// call -- before the fork's caller even reached this function, during a
/// slow drop, between the drop and this very registration -- has already
/// reparented the worker by the time `getppid` is read here, no matter
/// when in that window the death happened, so one check right after each
/// arming is sufficient; it does not need an earlier copy of itself.
fn arm_and_verify_pdeathsig(helper_pid: nix::unistd::Pid) -> anyhow::Result<()> {
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
        .context("registering the parent-death signal")?;
    if nix::sys::prctl::get_pdeathsig().context("reading back the parent-death signal")?
        != Some(nix::sys::signal::Signal::SIGKILL)
    {
        anyhow::bail!("the parent-death signal did not take -- refusing to run without it");
    }
    if nix::unistd::getppid() != helper_pid {
        anyhow::bail!("the helper was already gone before the worker could finish starting");
    }
    Ok(())
}

/// Split into helper and worker, and never return as both.
///
/// Called before the tokio runtime is built -- that is the whole point. The
/// helper stays single-threaded for life; the worker starts its threads only
/// after the fork has already happened. This is enforced here, at run time,
/// not merely documented: see the thread-count check below, which refuses
/// to fork at all once it is no longer true.
///
/// Each half watches the other, in both directions:
/// - The worker sees the seam close when the helper dies, because the
///   kernel closes every descriptor a dead process held -- no cooperation
///   from the helper is needed for that half.
/// - The helper already sees the same when the worker's copy of either seam
///   closes (`server::run_with_diagnostics`'s loop ends the moment `recv` on either reports
///   the peer gone).
///
/// A worker cannot rely on the same kernel mechanism to notice a dead
/// helper as quickly, since normally-running code never touches the seam
/// except to send a request or read one, so a helper dying between
/// requests could go unnoticed indefinitely -- and a LATER slice's PAM
/// child, forked between the helper's fork and its exec, could hold the
/// helper's end of the seam open even after the helper itself is gone,
/// defeating the kernel-close signal the worker's reader threads rely on
/// entirely. Two mechanisms close that gap, belt and suspenders:
/// `PR_SET_PDEATHSIG`, armed TWICE by the child (`arm_and_verify_pdeathsig`,
/// once right after the fork and again right after
/// `drop_worker_privileges`, because that drop's own uid/gid change clears
/// the setting -- `prctl(2)` says so -- and the first arming exists so an
/// NSS lookup inside the drop that hangs or is merely slow does not leave
/// the worker unwatched for however long it takes), asks the kernel to end
/// the worker with `SIGKILL` the moment its parent thread (the helper,
/// which never spawns another) ends, for any reason; and each of the
/// worker's two reader threads, one per seam
/// (`spawner::HelperChannelSpawner::new_with_hook`,
/// `spawner::HelperAuth::new_with_hook`), ends the process itself the
/// moment it notices its seam closed for a reason other than the worker's
/// own `Drop` -- the authentication seam's reader also when it stops for any
/// other reason, since then no verdict can reach the worker. Both are wired
/// in `spawner::worker_clients` -- the only way the daemon can build those
/// clients at all, since their constructors are private or test-only --
/// where tests without root watch the wiring end a real process
/// (`the_worker_ends_once_*_seam_is_lost`); under root,
/// `qshd/tests/serve_system_split.rs` watches the authentication seam's half
/// end the real worker on its own. `SIGKILL`,
/// not `SIGTERM`: reading `get_pdeathsig` back only proves the setting
/// took, not that delivering it would
/// actually end the process -- a `SIGTERM` inherited as `SIG_IGN`, or
/// caught by a handler some future change installs for its own reasons,
/// would still read back correctly and still do nothing. `SIGKILL` cannot
/// be blocked, caught or ignored by anything, ever. This does not collide
/// with an ordinary `systemctl stop`: `KillMode=control-group` (the
/// default) sends ITS OWN `SIGTERM` directly to every process in the
/// unit's cgroup, worker included, for an orderly stop -- a signal
/// delivered independently of this mechanism, which exists only to catch
/// the helper disappearing WITHOUT a normal stop in progress, where there
/// is nothing left worth a graceful shutdown for: the pty-owning half is
/// already gone. One real cost of that choice: if the helper dies from
/// its OWN copy of that same `SIGTERM` (an ordinary stop hits the whole
/// cgroup, helper included) rather than being killed outright, this
/// mechanism still fires once the helper actually exits -- so a worker
/// that some future change teaches to trap ITS `SIGTERM` and shut down
/// its own sessions gracefully could still have that shutdown cut off by
/// this `SIGKILL` arriving first, depending on which of the two finishes
/// sooner; nothing here orders them relative to each other. Either death
/// ends the service, and the service manager restarts it whole. A half alive without its other half would be worse
/// than a clean exit: sessions still running, new ones impossible, and
/// nothing in the log to say why -- and, once the helper is privileged and
/// the worker is not, an unprivileged process outliving the privileged one
/// it depends on while still holding the listening port and every other
/// session's pty is not merely an inconvenience.
pub fn split_and_run(
    config: HelperConfig,
    run_worker: impl FnOnce(
        spawner::HelperChannelSpawner,
        spawner::HelperAuth,
        transport::session_manager::LoginEndedReports,
    ) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    // A multi-threaded `fork` leaves the child holding locks -- the
    // allocator's among them -- that nobody in it will ever release, since
    // the thread that held them does not exist there. Refusing outright,
    // rather than documenting the precondition and hoping every caller
    // reads it, is what actually enforces "the helper is born
    // single-threaded": see `split_and_run_refuses_a_multi_threaded_process`
    // below, which calls this function for real (inside the ordinary test
    // harness, which is never single-threaded) and asserts the refusal.
    let threads = std::fs::read_dir("/proc/self/task")
        .context("counting this process's threads before forking")?
        .count();
    if threads != 1 {
        anyhow::bail!(
            "refusing to fork with {threads} threads already running in this process -- a \
             multi-threaded fork would leave the child holding locks (the allocator's among \
             them) that nobody in it will ever release; split_and_run must run before anything \
             else in the process starts a thread"
        );
    }

    // Two seams, not one, each with a reader thread of its own on the
    // worker's side. The channel seam's demultiplexes replies, descriptors
    // and unprompted `Exited` notices by channel id
    // (`spawner::HelperChannelSpawner`); the authentication seam's hands
    // each answer to the call that asked by request number
    // (`spawner::HelperAuth`). Neither has to understand the other's
    // stream. The helper serves both from its one loop.
    let (worker_channels, helper_channels) =
        channel::pair().context("creating the channel seam's socket pair")?;
    let (worker_auth, helper_auth) =
        channel::pair().context("creating the authentication seam's socket pair")?;
    let (worker_log, mut helper_log) =
        crate::log::relay::pair().context("creating the diagnostic socket pair")?;

    // The pid that becomes the child's parent, captured before the fork so
    // the child can tell a helper that died in the narrow window between
    // the fork and its own first `arm_and_verify_pdeathsig` call (below)
    // apart from one still alive: a child reparented in that window no
    // longer has this pid as its parent by the time it can check.
    let helper_pid = nix::unistd::getpid();

    // SAFETY: the thread count checked above was exactly 1 at the point of
    // the check, and nothing between there and here starts another thread
    // -- so the fork happens single-threaded, and the child inherits no
    // lock held by a thread that does not exist in it.
    match unsafe { nix::unistd::fork() }.context("splitting into helper and worker")? {
        nix::unistd::ForkResult::Parent { child } => {
            // The helper has no business with the network: drop the worker's
            // ends of both pairs here and let the worker own them alone.
            drop(worker_channels);
            drop(worker_auth);
            drop(worker_log);
            helper_log.set_worker_pid(child.as_raw() as u32);
            // `run_worker` closes over the UDP socket (bound before this
            // split, in `serve.rs`, and moved in by the caller) even though
            // the helper never calls it. `server::run_with_diagnostics` below never returns
            // -- it ends the process itself -- so the normal end-of-scope
            // drop glue that would release `run_worker` never runs either.
            // Dropping it here, explicitly, is what actually closes the
            // helper's inherited copy of the network descriptor: the
            // invariant this whole split exists for is that the privileged
            // process holds no network descriptor at all.
            drop(run_worker);
            server::run_with_diagnostics(helper_channels, helper_auth, config, helper_log)
        }
        nix::unistd::ForkResult::Child => {
            drop(helper_channels);
            drop(helper_auth);
            drop(helper_log);
            crate::log::use_worker_relay(worker_log)
                .context("releasing the worker's privileged log descriptor")?;

            // Armed once now, right after the fork, and again after the
            // drop below -- see `arm_and_verify_pdeathsig`'s docs and this
            // module's for why both, and why `SIGKILL`.
            arm_and_verify_pdeathsig(helper_pid)?;

            // The half that parses everything a stranger sends must not
            // stay root. Dropped here, as early as possible -- before the
            // spawner, before any thread, before the tokio runtime
            // `run_worker` builds -- rather than deferred until the worker
            // is already doing real work.
            drop_worker_privileges(&config.worker_user)
                .context("dropping the worker's privileges")?;

            // The drop above just cleared the arming above -- `prctl(2)`
            // documents `PR_SET_PDEATHSIG` as cleared by a change to the
            // effective user or group id -- so it is redone here, not
            // merely reasserted once at the top.
            arm_and_verify_pdeathsig(helper_pid)?;

            // Handed `config` -- the very settings the helper runs with on
            // the other side of this fork. No test sees which settings this
            // line passes (see `worker_clients`); it is the only one in scope.
            let (spawner, auth, login_ends) =
                spawner::worker_clients(worker_channels, worker_auth, &config)?;
            run_worker(spawner, auth, login_ends)
        }
    }
}

/// Ends the worker, saying `why` -- in the log, and on stderr, which a
/// service manager keeps with the restart it is about to make. Called when
/// the worker can no longer do its job: a seam reader found its helper gone,
/// a login's end could not be kept for the helper, or a thread the worker
/// cannot admit anyone without has stopped (the release thread, the nonce
/// pool's). See `split_and_run`'s docs for why a worker in any of those
/// states must not run on.
pub(crate) fn end_the_worker(why: &str) {
    // `loud`: on stderr as well, whether or not this process mirrors every
    // line there -- written without `eprintln!`, which panics on a write
    // error, and stderr may well be closed by now.
    crate::log::loud(
        crate::log::Level::Error,
        "worker",
        &format!("ending the process -- {why}"),
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal itself, exercised for real. libtest always runs a
    /// test's body on a thread it spawns for that purpose, in addition to
    /// its own control thread, on any platform that supports threads at
    /// all -- unconditionally, regardless of `--test-threads` (that flag
    /// bounds how many tests run concurrently, not whether each one's body
    /// gets a thread of its own). So this test, running as an ordinary
    /// `#[test]` inside the standard harness, is guaranteed to see more
    /// than one thread here, and `split_and_run` must refuse rather than
    /// actually forking the test binary.
    #[test]
    fn split_and_run_refuses_a_multi_threaded_process() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let called = Arc::new(AtomicBool::new(false));
        let called_in_closure = Arc::clone(&called);
        let config = HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: false,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: server::STARTUP_REPORT_TIMEOUT,
            verify_timeout: server::VERIFY_TIMEOUT,
            pam_service: config::PAM_SERVICE.to_string(),
            pam_confdir: None,
        };
        let err = split_and_run(config, move |_spawner, _auth, _login_ends| {
            called_in_closure.store(true, Ordering::SeqCst);
            Ok(())
        })
        .expect_err("a harnessed test binary already has more than one thread");

        assert!(
            !called.load(Ordering::SeqCst),
            "the worker closure must never run when the fork itself is refused"
        );
        assert!(
            err.to_string().contains("threads"),
            "the error should say why the fork was refused, got: {err}"
        );
    }

    /// Reachable without root: an unknown worker account must be an error,
    /// not a silent pass. Exercises the same path `run_serve_command` takes
    /// for a mistyped `--worker-user`.
    #[test]
    fn drop_worker_privileges_refuses_an_unknown_account() {
        let err = drop_worker_privileges("definitely-no-such-account-here")
            .expect_err("an unknown worker account must be an error, not a silent pass");
        assert!(
            err.to_string().contains("looking up the worker account"),
            "the error should say which step failed, got: {err}"
        );
    }

    /// Reachable without root, and checked BEFORE any privileged call: a
    /// worker account that resolves to uid 0 (the `root` account always
    /// exists) would otherwise pass every id check this function makes
    /// trivially, while leaving the worker exactly as privileged as it
    /// started.
    #[test]
    fn drop_worker_privileges_refuses_a_root_worker_account() {
        let err = drop_worker_privileges("root")
            .expect_err("a worker account that resolves to uid 0 must be refused");
        assert!(
            err.to_string()
                .contains("refusing to run the network-facing worker as root"),
            "the error should say why, got: {err}"
        );
    }

    /// Pure and reachable without root: the three ways an account can carry
    /// root privilege that `drop_worker_privileges` itself cannot see once
    /// it is only checking whether ITS OWN ids/groups took -- its own uid,
    /// its own primary group, or gid 0 hiding among its supplementary
    /// groups (the case a real account with that shape is hard to find on
    /// an ordinary machine to exercise any other way).
    #[test]
    fn account_is_privileged_catches_uid_gid_and_supplementary_root() {
        let unprivileged = account::Account {
            uid: nix::unistd::Uid::from_raw(1000),
            gid: nix::unistd::Gid::from_raw(1000),
            name: "nobody-in-particular".to_string(),
            home: "/home/nobody-in-particular".into(),
            shell: "/bin/sh".into(),
            groups: vec![nix::unistd::Gid::from_raw(1000)],
        };
        assert!(
            !account_is_privileged(&unprivileged),
            "a plain account must not be flagged"
        );
        assert!(account_is_privileged(&account::Account {
            uid: nix::unistd::Uid::from_raw(0),
            ..unprivileged.clone()
        }));
        assert!(account_is_privileged(&account::Account {
            gid: nix::unistd::Gid::from_raw(0),
            ..unprivileged.clone()
        }));
        assert!(account_is_privileged(&account::Account {
            groups: vec![
                nix::unistd::Gid::from_raw(1000),
                nix::unistd::Gid::from_raw(0)
            ],
            ..unprivileged
        }));
    }

    /// Reachable without root: parsing this process's own capability sets
    /// from `/proc/self/status` must succeed and produce well-formed
    /// numbers. An ordinary unprivileged test process has nothing in any of
    /// the three sets this cares about, which doubles as a sanity check
    /// that the hex parsing above lines up with the real format.
    #[test]
    fn own_capability_sets_parses_and_reports_none_for_an_ordinary_process() {
        if nix::unistd::Uid::effective().is_root() {
            eprintln!(
                "SKIPPED own_capability_sets_parses_and_reports_none_for_an_ordinary_process: \
                 root may hold real capabilities, which this test assumes away."
            );
            return;
        }
        let caps = own_capability_sets().expect("parse /proc/self/status");
        assert_eq!(
            caps.permitted, 0,
            "an ordinary process holds no permitted capabilities"
        );
        assert_eq!(
            caps.effective, 0,
            "an ordinary process holds no effective capabilities"
        );
        assert_eq!(
            caps.ambient, 0,
            "an ordinary process holds no ambient capabilities"
        );
    }

    /// Pure and reachable without root: a kernel older than Linux 4.3 has
    /// no `CapAmb:` line in `/proc/self/status` at all (ambient
    /// capabilities did not exist yet) -- its absence must read as zero,
    /// not as a parse failure, or the system mode would refuse to start on
    /// such a kernel outright over a field it never had reason to expect.
    #[test]
    fn parse_capability_sets_treats_a_missing_ambient_line_as_zero() {
        let status = "Name:\tqshd\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n";
        let caps = parse_capability_sets(status).expect("a missing CapAmb line is not an error");
        assert_eq!(caps.permitted, 0);
        assert_eq!(caps.effective, 0);
        assert_eq!(caps.ambient, 0, "a missing CapAmb line must read as zero");
    }

    /// The other half of the same fix: `CapPrm`/`CapEff` are NOT given the
    /// same leniency -- they have existed since Linux capabilities were
    /// introduced, decades before this codebase's minimum kernel, so their
    /// absence means something is genuinely wrong with how `/proc` was
    /// read, not merely that this is a machine of a certain age.
    #[test]
    fn parse_capability_sets_still_requires_permitted_and_effective() {
        let status = "Name:\tqshd\nCapAmb:\t0000000000000000\n";
        assert!(parse_capability_sets(status).is_err());
    }

    /// Also reachable without root: `setgroups` alone requires `CAP_SETGID`
    /// regardless of the target list, so this call is refused even for a
    /// real, existing account (this test's own) when the test process is
    /// not root -- which is how this suite runs, here and in CI.
    ///
    /// Skipped, loudly, on the rare run that IS root: succeeding there would
    /// setuid the TEST PROCESS itself, permanently and irreversibly (this is
    /// the whole point of `setuid`'s ordering, see this function's docs),
    /// corrupting every other test sharing the binary. The actual successful
    /// drop, and the proof-it-took check after it, are exercised only by a
    /// later, root-only end-to-end test in this plan that forks a throwaway
    /// process for it instead of running inside the shared test binary.
    #[test]
    fn drop_worker_privileges_refuses_without_root() {
        if nix::unistd::Uid::effective().is_root() {
            eprintln!(
                "SKIPPED drop_worker_privileges_refuses_without_root: running as root would \
                 make this call SUCCEED, permanently changing this test process's identity."
            );
            return;
        }
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .expect("passwd")
            .expect("the current account exists");
        let err = drop_worker_privileges(&me.name)
            .expect_err("dropping privileges without root must fail, not silently succeed");
        assert!(
            err.to_string().contains("setting the worker's groups"),
            "setgroups is the first privileged call and needs CAP_SETGID regardless of the \
             target list, so it should be the one that fails here, got: {err}"
        );
    }

    /// `ensure_standard_descriptors` puts `/dev/null` on a closed standard
    /// descriptor and leaves the open ones alone. The check has to close
    /// descriptor 0 for a moment, and any other test in this binary that
    /// opened something in that moment could be handed 0 itself -- so the
    /// check runs in a process of its own: this test re-invokes the test
    /// binary selecting only `..._body`, the way `channel`'s
    /// descriptor-leak check does.
    #[test]
    fn a_closed_standard_descriptor_is_pointed_at_dev_null() {
        // One named constant, because the failure message quotes it: whoever
        // renames the `_body` test needs the exact string to change.
        const INNER: &str =
            "helper::tests::a_closed_standard_descriptor_is_pointed_at_dev_null_body";

        let exe = std::env::current_exe().expect("current_exe");
        let output = std::process::Command::new(exe)
            .args([INNER, "--exact", "--ignored", "--test-threads=1"])
            .output()
            .expect("spawn the isolated check");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // A filter that matches nothing still exits 0: insist it ran one.
        assert!(
            stdout.contains("running 1 test\n"),
            "expected the filter to match exactly one test -- `{INNER}` does not exist under \
             that name any more?\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            output.status.success(),
            "the isolated check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// The check itself, only meaningful alone in its process -- the test
    /// above is what runs it. Descriptor 0 is closed, the function runs,
    /// and 0 must then be `/dev/null`, while 1 and 2 are still exactly what
    /// they were.
    #[test]
    #[ignore = "runs only via a_closed_standard_descriptor_is_pointed_at_dev_null, in a process \
                of its own"]
    fn a_closed_standard_descriptor_is_pointed_at_dev_null_body() {
        use nix::sys::stat::{fstat, stat};

        let identity = |fd| fstat(fd).map(|st| (st.st_dev, st.st_ino));
        let before = [identity(1).expect("fd 1"), identity(2).expect("fd 2")];
        let saved = nix::unistd::dup(0).expect("keep descriptor 0");
        nix::unistd::close(0).expect("close descriptor 0");

        let result = ensure_standard_descriptors();
        let reopened = identity(0);
        // The real descriptor 0 goes back before any assertion can end this
        // function early.
        nix::unistd::dup2(saved, 0).expect("restore descriptor 0");
        let _ = nix::unistd::close(saved);

        result.expect("ensure_standard_descriptors must succeed");
        let null = stat("/dev/null").expect("stat /dev/null");
        assert_eq!(
            reopened.expect("descriptor 0 must be open again"),
            (null.st_dev, null.st_ino),
            "descriptor 0 must now be /dev/null"
        );
        assert_eq!(
            [identity(1).expect("fd 1"), identity(2).expect("fd 2")],
            before,
            "descriptors that were open must be left alone"
        );
    }

    /// `refuse_dangerous_securebits` passes for an ordinary process, whose
    /// securebits are clear.
    #[test]
    fn refuse_dangerous_securebits_passes_when_none_are_set() {
        refuse_dangerous_securebits()
            .expect("an ordinary process has neither SECBIT set and must be allowed");
    }

    /// With `SECBIT_NO_SETUID_FIXUP` set, the system mode refuses to start.
    /// Setting a securebit needs `CAP_SETPCAP` and would corrupt the shared
    /// test binary, so this re-executes a `_body` under `setpriv`, which sets
    /// the bit for that child alone. Root-only, and `setpriv` (util-linux)
    /// required; skipped, loudly, otherwise.
    #[test]
    fn the_system_mode_refuses_a_dangerous_securebit() {
        const INNER: &str = "helper::tests::the_system_mode_refuses_a_dangerous_securebit_body";
        if !nix::unistd::Uid::effective().is_root() {
            eprintln!(
                "SKIPPED the_system_mode_refuses_a_dangerous_securebit: setting a securebit \
                 needs root (CAP_SETPCAP)."
            );
            return;
        }
        if std::process::Command::new("setpriv")
            .arg("--help")
            .output()
            .is_err()
        {
            eprintln!(
                "SKIPPED the_system_mode_refuses_a_dangerous_securebit: `setpriv` (util-linux) \
                 is needed to set the securebit."
            );
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        let output = std::process::Command::new("setpriv")
            .arg("--securebits=+noroot,+no_setuid_fixup")
            .arg(exe)
            .args([
                INNER,
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .expect("run the body under setpriv");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("running 1 test\n"),
            "expected the filter to match exactly one test -- `{INNER}` renamed?\nstdout:\n\
             {stdout}\nstderr:\n{stderr}"
        );
        assert!(
            output.status.success(),
            "the system mode must refuse a dangerous securebit:\nstdout:\n{stdout}\nstderr:\n\
             {stderr}"
        );
    }

    /// Runs only via [`the_system_mode_refuses_a_dangerous_securebit`], in a
    /// process `setpriv` has given `SECBIT_NO_SETUID_FIXUP`.
    #[test]
    #[ignore = "runs only via the_system_mode_refuses_a_dangerous_securebit, under setpriv"]
    fn the_system_mode_refuses_a_dangerous_securebit_body() {
        let err = refuse_dangerous_securebits()
            .expect_err("with SECBIT_NO_SETUID_FIXUP set the system mode must refuse to start");
        assert!(
            err.to_string().contains("SECBIT_NO_SETUID_FIXUP"),
            "the refusal must name the offending securebit, got: {err}"
        );
    }

    /// How long a `worker_clients` body waits for `end_the_worker` before
    /// concluding that nothing will call it.
    const WORKER_CLIENTS_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    /// How long the parent waits for a `worker_clients` body's process: well
    /// past [`WORKER_CLIENTS_WAIT`], which bounds the body itself, so only a
    /// process that is stuck for some other reason runs into it.
    const WORKER_CLIENTS_PROCESS_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

    /// The exit code of a `worker_clients` body that failed. `end_the_worker`
    /// exits with 1, and a panicking test binary with 101.
    const WORKER_CLIENTS_BODY_FAILED: i32 = 2;

    /// Settings no production value matches, so clients built from any
    /// other settings show.
    fn worker_clients_config() -> HelperConfig {
        HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: false,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: server::STARTUP_REPORT_TIMEOUT,
            verify_timeout: std::time::Duration::from_secs(3),
            pam_service: config::PAM_SERVICE.to_string(),
            pam_confdir: None,
        }
    }

    /// How a `worker_clients` body fails: at once, with a code of its own,
    /// and WITHOUT unwinding. Unwinding drops the body's locals, the
    /// helper's end of the seam still open among them. As the bodies are
    /// written that is harmless on its own: the clients, declared later, are
    /// dropped first and mark their disconnects as their own, so no reader
    /// calls `end_the_worker`. But with the declarations in another order,
    /// or a `Drop` that failed to mark its disconnect -- a second fault on
    /// top of the one being reported -- the reader on that seam would end
    /// the process through `end_the_worker`, the very effect the body
    /// watches for, and turn the failure into a pass. Not unwinding at all
    /// takes that dependence away.
    fn fail_worker_clients_body(why: &str) -> ! {
        eprintln!("{why}");
        std::process::exit(WORKER_CLIENTS_BODY_FAILED);
    }

    /// Runs one `worker_clients` body in a process of its own and insists
    /// it ended through `end_the_worker`, which exits with 1, giving `why`
    /// on stderr. The wait for that process is bounded too: one that never
    /// ends is killed, and the test fails rather than hangs.
    fn worker_clients_body_ends_its_process(inner: &str, why: &str) {
        use std::io::Read;

        let exe = std::env::current_exe().expect("current_exe");
        let mut child = std::process::Command::new(exe)
            .args([
                inner,
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the isolated check");
        let mut stdout_pipe = child.stdout.take().expect("the child's stdout");
        let mut stderr_pipe = child.stderr.take().expect("the child's stderr");
        let stdout_reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut out);
            out
        });
        let stderr_reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut out);
            out
        });
        let deadline = std::time::Instant::now() + WORKER_CLIENTS_PROCESS_WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait for the isolated check") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the isolated check `{inner}` was still running after \
                     {WORKER_CLIENTS_PROCESS_WAIT:?}; killed"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let stdout = String::from_utf8_lossy(&stdout_reader.join().expect("join")).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_reader.join().expect("join")).into_owned();
        assert!(
            stdout.contains("running 1 test\n"),
            "expected the filter to match exactly one test -- `{inner}` renamed?\nstdout:\n\
             {stdout}\nstderr:\n{stderr}"
        );
        assert_eq!(
            status.code(),
            Some(1),
            "the worker must end itself (end_the_worker exits with 1):\nstdout:\n{stdout}\n\
             stderr:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("ERROR worker: ending the process -- {why}")),
            "the worker must say why it ended ({why:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// The wiring `split_and_run`'s worker gets, seen in a real process
    /// without root: losing only the authentication seam ends the process,
    /// and the verdict wait comes from the settings handed in.
    #[test]
    fn the_worker_ends_once_its_authentication_seam_is_lost() {
        worker_clients_body_ends_its_process(
            "helper::tests::the_worker_ends_once_its_authentication_seam_is_lost_body",
            spawner::HELPER_GONE_REASON,
        );
    }

    /// Runs only via [`the_worker_ends_once_its_authentication_seam_is_lost`],
    /// in a process of its own: `end_the_worker` ends the whole process.
    #[test]
    #[ignore = "runs only via the_worker_ends_once_its_authentication_seam_is_lost, in a process \
                of its own"]
    fn the_worker_ends_once_its_authentication_seam_is_lost_body() {
        let (worker_channels, helper_channels) = channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = channel::pair().expect("socketpair");
        let config = worker_clients_config();
        let (_spawner, auth, _login_ends) =
            spawner::worker_clients(worker_channels, worker_auth, &config).unwrap_or_else(|e| {
                fail_worker_clients_body(&format!("the worker's clients: {e:#}"))
            });
        let waited = auth.verify_timeout();
        if !(waited > config.verify_timeout
            && waited < config.verify_timeout + spawner::HELPER_ANSWER_TIMEOUT)
        {
            fail_worker_clients_body(&format!(
                "the verdict wait must come from the settings handed in ({:?}), got {waited:?}",
                config.verify_timeout
            ));
        }
        // Only the authentication seam goes; the channel seam stays open for
        // the whole wait, so its reader has nothing to act on.
        drop(helper_auth);
        std::thread::sleep(WORKER_CLIENTS_WAIT);
        let _still_open = &helper_channels;
        fail_worker_clients_body(&format!(
            "still running {WORKER_CLIENTS_WAIT:?} after the authentication seam was lost: \
             nothing ended the worker"
        ));
    }

    /// The same, for the channel seam.
    #[test]
    fn the_worker_ends_once_its_channel_seam_is_lost() {
        worker_clients_body_ends_its_process(
            "helper::tests::the_worker_ends_once_its_channel_seam_is_lost_body",
            spawner::HELPER_GONE_REASON,
        );
    }

    /// Runs only via [`the_worker_ends_once_its_channel_seam_is_lost`], in a
    /// process of its own.
    #[test]
    #[ignore = "runs only via the_worker_ends_once_its_channel_seam_is_lost, in a process of its \
                own"]
    fn the_worker_ends_once_its_channel_seam_is_lost_body() {
        let (worker_channels, helper_channels) = channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = channel::pair().expect("socketpair");
        let (_spawner, _auth, _login_ends) =
            spawner::worker_clients(worker_channels, worker_auth, &worker_clients_config())
                .unwrap_or_else(|e| {
                    fail_worker_clients_body(&format!("the worker's clients: {e:#}"))
                });
        drop(helper_channels);
        std::thread::sleep(WORKER_CLIENTS_WAIT);
        let _still_open = &helper_auth;
        fail_worker_clients_body(&format!(
            "still running {WORKER_CLIENTS_WAIT:?} after the channel seam was lost: nothing \
             ended the worker"
        ));
    }
    /// The same wiring, for the promise the authentication client makes about
    /// the ends of logins: one that no longer fits in its queue ends the
    /// worker rather than being dropped.
    #[test]
    fn the_worker_ends_rather_than_drop_the_end_of_a_login() {
        worker_clients_body_ends_its_process(
            "helper::tests::the_worker_ends_rather_than_drop_the_end_of_a_login_body",
            spawner::LOGIN_ENDS_OVERFLOW_REASON,
        );
    }

    /// Runs only via [`the_worker_ends_rather_than_drop_the_end_of_a_login`],
    /// in a process of its own. Both seams stay open, and nothing is read
    /// from them: the queue fills without anything being sent.
    #[test]
    #[ignore = "runs only via the_worker_ends_rather_than_drop_the_end_of_a_login, in a process \
                of its own"]
    fn the_worker_ends_rather_than_drop_the_end_of_a_login_body() {
        use transport::session_manager::LoginSink;

        let (worker_channels, helper_channels) = channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = channel::pair().expect("socketpair");
        let (_spawner, auth, _login_ends) =
            spawner::worker_clients(worker_channels, worker_auth, &worker_clients_config())
                .unwrap_or_else(|e| {
                    fail_worker_clients_body(&format!("the worker's clients: {e:#}"))
                });
        let login = |n: usize| {
            let mut login = [0u8; 16];
            login[..8].copy_from_slice(&(n as u64).to_be_bytes());
            login
        };
        for n in 0..spawner::MAX_QUEUED_LOGIN_ENDS {
            auth.queue_only_for_test(protocol::Request::LoginEnded { login: login(n) });
        }
        auth.login_ended(login(spawner::MAX_QUEUED_LOGIN_ENDS));
        std::thread::sleep(WORKER_CLIENTS_WAIT);
        let _still_open = (&helper_channels, &helper_auth);
        fail_worker_clients_body(&format!(
            "still running {WORKER_CLIENTS_WAIT:?} after a login's end did not fit in the queue: \
             nothing ended the worker"
        ));
    }

    /// The WIRING itself, which nothing else can see: `worker_clients` must
    /// hand the spawner's reader the reporting half of the very reports it
    /// hands back, not a sink that goes nowhere.
    ///
    /// Both ends of this path are pinned elsewhere -- the reader forwards
    /// what it reads
    /// (`spawner::tests::a_login_ended_from_the_helper_reaches_the_router`),
    /// and the router acts on what it is given
    /// (`transport`'s own
    /// `a_login_ended_from_outside_tears_down_its_backend_through_serve`) --
    /// and with the closure below replaced by `Box::new(|_| {})` every one
    /// of them stays green. This is the one test that fails.
    ///
    /// No root and no fork: `worker_clients` is a plain constructor, and
    /// what it wires together is visible from inside one process.
    #[tokio::test]
    async fn worker_clients_wires_the_helpers_login_ends_to_the_reports_it_hands_back() {
        let (worker_channels, helper_channels) = channel::pair().expect("socketpair");
        let (worker_auth, _helper_auth) = channel::pair().expect("socketpair");
        let (_spawner, _auth, mut login_ends) =
            spawner::worker_clients(worker_channels, worker_auth, &worker_clients_config())
                .expect("the worker's clients");

        let login = [77u8; 16];
        let incarnation = 3u64;
        let news = protocol::encode(&protocol::Response::LoginEnded { login, incarnation })
            .expect("encode");
        channel::send(&helper_channels, &news, None).expect("report the end of a login");

        let reported = tokio::time::timeout(WORKER_CLIENTS_WAIT, login_ends.recv())
            .await
            .expect("the end of a login must reach the router's half, bounded");
        assert_eq!(
            reported,
            Some((login, incarnation)),
            "what the helper reported must arrive at the half `worker_clients` hands the \
             router, incarnation and all"
        );
    }

    /// The same promise in the OTHER direction, bounded by the same
    /// constant: an end of a login the HELPER reported that no longer fits
    /// in the router's queue ends the worker rather than being dropped. A
    /// session whose login has ended and whose router was never told goes
    /// on answering pings while every channel it asks for is refused.
    #[test]
    fn the_worker_ends_rather_than_drop_a_login_end_the_helper_reported() {
        worker_clients_body_ends_its_process(
            "helper::tests::the_worker_ends_rather_than_drop_a_login_end_the_helper_reported_body",
            spawner::HELPER_LOGIN_ENDS_OVERFLOW_REASON,
        );
    }

    /// Runs only via
    /// [`the_worker_ends_rather_than_drop_a_login_end_the_helper_reported`],
    /// in a process of its own. The router's half of the reports is held
    /// and never drained -- exactly what a router wedged on its own task
    /// looks like from here -- and the helper's end of the channel seam
    /// reports one login more than the queue holds.
    #[test]
    #[ignore = "runs only via the_worker_ends_rather_than_drop_a_login_end_the_helper_reported, \
                in a process of its own"]
    fn the_worker_ends_rather_than_drop_a_login_end_the_helper_reported_body() {
        let (worker_channels, helper_channels) = channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = channel::pair().expect("socketpair");
        let (_spawner, _auth, _login_ends) =
            spawner::worker_clients(worker_channels, worker_auth, &worker_clients_config())
                .unwrap_or_else(|e| {
                    fail_worker_clients_body(&format!("the worker's clients: {e:#}"))
                });
        // One more than the queue holds. Sent one at a time, so the seam
        // itself never has to hold them all: the worker's reader takes each
        // off it at once and it is the ROUTER's queue, which nothing
        // drains, that fills.
        for n in 0..=spawner::MAX_QUEUED_LOGIN_ENDS {
            let mut login = [0u8; 16];
            login[..8].copy_from_slice(&(n as u64).to_be_bytes());
            let news = protocol::encode(&protocol::Response::LoginEnded {
                login,
                incarnation: 1 + n as u64,
            })
            .unwrap_or_else(|e| fail_worker_clients_body(&format!("encoding a notice: {e}")));
            if let Err(e) = channel::send(&helper_channels, &news, None) {
                fail_worker_clients_body(&format!("reporting a login ended: {e}"));
            }
        }
        std::thread::sleep(WORKER_CLIENTS_WAIT);
        let _still_open = (&helper_channels, &helper_auth);
        fail_worker_clients_body(&format!(
            "still running {WORKER_CLIENTS_WAIT:?} after a login the helper reported ended did \
             not fit in the router's queue: nothing ended the worker"
        ));
    }
}
