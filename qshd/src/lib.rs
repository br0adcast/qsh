//! Library part of the `qshd` daemon.
//!
//! The qsh path (QUIC/quinn/mTLS, the `quic`/`session`/`roles`/`ports`
//! modules and the mTLS half of `state`) has been removed -- replaced by
//! the NEW transport (`crates/transport`, Noise over UDP), driven by
//! [`transport_daemon`].
//!
//! [`state`] -- executable version/build/checksum (`QSHD_VERSION`/
//! `build_label`/`self_checksum`), shared by both paths (also used by
//! qsh). [`pty`] -- launching `$SHELL` (or, for a command channel, the
//! command a client asked for) in a pseudo-terminal. [`control`] -- the
//! control Unix socket protocol (`STATUS`/`ADD-CLIENT`/`STOP`, plus
//! `ADD-PORT`, which is parseable but not applicable to the new transport):
//! types, the line-based codec, and the synchronous `client_request` client
//! -- used by `transport-ensure` in `main.rs` to first ask a live daemon
//! instead of blindly starting a second one; the async server for this
//! protocol is separate per path (qsh had `serve_control`, the new
//! transport now has `transport_daemon::serve_transport_control`).
//! [`version`] -- the pure `reconcile` version-negotiation decision for
//! `ensure`/`transport-ensure` when a daemon is already alive.
//! [`transport_daemon`] -- daemonization of the `transport-ensure`
//! subcommand: the new transport daemon's body after forking (the channel
//! session router plus the `STATUS`/`ADD-CLIENT`/`STOP` control server in
//! one runtime) and the pure reuse/allowlist decisions called by
//! `main.rs::run_transport_ensure`. The allowlist of
//! client Noise keys (X25519, `transport::Connection`) is IN-MEMORY ONLY,
//! held as [`transport_daemon::SharedAllowlist`] -- the on-disk half that
//! used to live in a separate `transport_state` module was retired: a
//! live, self-cleaning allowlist has no durable copy to keep in sync.
//!
//! [`serve`] -- the standing-service path: `qshd serve`, a long-lived
//! daemon on a fixed UDP port that authenticates every client by an SSH
//! signature ([`sshauth::verify::AuthorizedKeysVerifier`]) instead of the
//! SSH-bootstrapped allowlist `transport-ensure` uses. It does not fork or
//! install itself -- a service manager owns the process (see
//! `docs/qshd-service.md`) -- so it reuses [`load_or_create_transport_key`]
//! for its own permanent host key but calls neither `transport_daemon` nor
//! `control`: there is no control socket and no version reconciliation to
//! do.
//!
//! [`channel_backend`] -- the `qshd` half of
//! `transport::channel_server::ChannelSpawner`, and the session backend BOTH
//! `serve` and `transport-ensure` hand to their session router
//! ([`channel_backend::ChannelSessionBackend`]): `qshd` hands out CHANNELS,
//! the way `sshd` does, rather than one fixed product per connection --
//! deciding what to put in a channel is the client's job, not the daemon's.
//! Opens a pseudo-terminal per channel, sized from the request itself
//! (never [`pty::DEFAULT_PTY_SIZE`] followed by a resize, which is what
//! used to make tmux reflow a pane and leave a blank line behind), and
//! builds a [`screen`] (a channel's server-side screen model, which is what
//! makes a repaint after a long absence possible) for the channels that
//! asked for one.
//!
//! [`handover`] -- handing a personal daemon's state to the binary that
//! replaces it in the same process.
//!
//! [`update`] -- the personal daemon's side of an update over qsh: the
//! decision, the staged image, the self-check and the replacement.

pub mod channel_backend;
pub mod control;
pub mod handover;
#[cfg(feature = "system")]
pub mod helper;
pub mod log;
#[cfg(feature = "system")]
pub mod nonce_pool;
#[cfg(target_os = "linux")]
mod process_scope;
pub mod pty;
pub mod screen;
pub mod screen_budget;
pub mod serve;
pub mod state;
pub mod transport_daemon;
pub mod update;
pub mod version;

mod host_key;
pub use host_key::{load_or_create_transport_key, load_transport_key};

/// The personal mode's source of handshake nonces -- one fresh, locally
/// minted value per handshake, with no privileged helper involved.
///
/// Re-exported rather than defined here: it lives in `transport`, the crate
/// that already depends on `rand`, so this crate needs no randomness
/// dependency of its own (and `cargo tree -p qshd -e normal` stays exactly
/// what it was before the system mode existed). The system mode's nonces
/// come from its privileged helper instead (`nonce_pool`, filled over the
/// same seam as the helper's verdicts), so a compromised worker cannot mint
/// its own.
pub use transport::RandomNonces;

/// The personal mode's [`transport::LoginSink`]: that daemon serves exactly
/// one login, keeps no PAM session tied to it, and holds nothing else keyed
/// by a login -- so there is nothing to do when one ends. Re-exported for
/// the same reason [`RandomNonces`] is: it lives in `transport`, not here.
pub use transport::ForgetNothing;

/// Shared test-only support, `pub(crate)` so more than one module's test
/// code can call into it.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod test_borrowed_scope;

#[cfg(test)]
pub(crate) mod test_support {
    #[cfg(target_os = "linux")]
    pub(crate) use crate::test_borrowed_scope as borrowed_scope;
    /// Several unit tests, spread across `pty` and `channel_backend`, spawn
    /// the invoking user's REAL `$SHELL` in a PTY (see
    /// `pty::spawn_shell`). Attached to a PTY that shell is interactive, so
    /// on exit it appends whatever it was fed to the launching user's own
    /// `~/.bash_history` -- not a sandboxed test fixture. Setting
    /// `HISTFILE=/dev/null` in THIS process before the first such spawn
    /// heads that off: a spawned child inherits the parent's environment,
    /// so every shell any test spawns inherits it too.
    ///
    /// `cargo test -p qshd --lib` builds every module of this crate into
    /// ONE test binary and runs their tests concurrently, on several
    /// threads of that one process, by default -- so this helper (and its
    /// `Once`) has to be shared across every module that spawns a shell,
    /// not local to any one of them: two independent, per-module `Once`s
    /// would still let their two unguarded `set_var` calls race each
    /// other, and the same process's `utf8_locale_env`/`env::var("SHELL")`
    /// reads race right along with them -- exactly the class of bug that
    /// later Rust versions address by making `set_var` unsafe under
    /// concurrency.
    pub(crate) fn suppress_shell_history() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| std::env::set_var("HISTFILE", "/dev/null"));
    }

    /// Tests that change the close-on-exec flags of this process's
    /// descriptors hold this, so one test's sweep (`close_on_exec_except`)
    /// never lands in the middle of another's check.
    pub(crate) fn fd_flags_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(all(test, feature = "system"))]
mod test_allocator;

// The shared fixture supervisor has no dependency on public production APIs.
#[cfg(all(test, target_os = "linux"))]
fn qualify_borrowed_fixture() {
    let _view =
        process_scope::prepare().expect("private fixture proc namespace/wait qualification");
}
