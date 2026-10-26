//! The helper's own settings, resolved once at startup -- before the fork,
//! not per channel.
//!
//! A couple of these settings come straight from [`crate::serve::ServeArgs`]
//! (already parsed from the command line by the time this runs); the `tty`
//! group is different -- looking it up is a database query (`getgrnam`, or
//! whatever NSS module answers it), and the privileged loop must not go back
//! to the database every time a client asks for a channel. Resolving it once
//! here, before the split, means the helper's loop never touches the
//! database again for the rest of its life.

use std::time::Duration;

use nix::unistd::Gid;

use crate::serve::ServeArgs;

/// The helper's settings, resolved once at startup.
///
/// `authorized_keys_template` and `permit_root` are read in the
/// verification path (`helper::server::verify_proof_after_nonce`); `tty_gid` names the
/// group a channel's terminal is given to (`helper::server::open_channel`).
pub struct HelperConfig {
    /// Where an account's authorized keys live; `%h` and `%u` expand.
    pub authorized_keys_template: String,
    /// Whether `uid 0` may log in.
    pub permit_root: bool,
    /// The group a terminal belongs to, resolved once at startup. Falls
    /// back to the account's own group on a machine with no `tty` group.
    pub tty_gid: Option<Gid>,
    /// The unprivileged account the worker drops to right after the fork
    /// (`helper::drop_worker_privileges`). Carried here rather than read
    /// straight off `ServeArgs` in the child branch of `split_and_run`,
    /// the same way every other helper setting reaches it.
    pub worker_user: String,
    /// How long a channel's child gets to report its own startup before the
    /// helper gives up on it, kills it and refuses the channel -- the
    /// deadline `helper::server`'s pending table hands the loop.
    ///
    /// A setting rather than the bare `helper::server::STARTUP_REPORT_TIMEOUT`
    /// so a test can watch that giving-up actually happen without sitting
    /// out the production budget; the daemon always resolves it to exactly
    /// that constant.
    pub startup_timeout: Duration,
    /// How long the child that checks one client's proof gets before the
    /// helper gives up on it, kills it and refuses that proof -- the
    /// deadline `helper::server`'s pending table hands the loop for a
    /// `PendingWhat::Verify` entry.
    ///
    /// A setting rather than the bare `helper::server::VERIFY_TIMEOUT` for
    /// exactly the reason [`HelperConfig::startup_timeout`] is one: a test
    /// has to be able to watch the giving-up happen without sitting out the
    /// production budget. The daemon always resolves it to that constant.
    pub verify_timeout: Duration,
    /// The PAM service a login's session is opened for -- the name of the
    /// stack in `/etc/pam.d`, which every monitor hands `pam_start`.
    ///
    /// Always [`PAM_SERVICE`] in the daemon, and deliberately NOT settable
    /// from the command line: which stack runs is the administrator's
    /// decision, made in `/etc/pam.d`, not something the line that starts
    /// the daemon may redirect. A setting only so a test can point a
    /// monitor at a stack of its own, beside
    /// [`HelperConfig::pam_confdir`].
    pub pam_service: String,
    /// The PAM configuration directory, for tests only. `None` in the
    /// daemon, where the stack is `/etc/pam.d/<service>` and nothing may
    /// redirect it. `Some(dir)` makes the monitor call `pam_start_confdir`
    /// instead of `pam_start`, which is what lets the PAM tests run
    /// unprivileged.
    ///
    /// `#[cfg(test)]`, like every other link in the chain that names
    /// `pam_start_confdir` (the declaration, `pam::Pam::start_confdir`, the
    /// branch in `pam::Pam::begin`, and the branch of
    /// `super::monitor::start_transaction` that reads this field). That
    /// function is versioned `@LIBPAM_1.4`, and one reference to it
    /// anywhere in the daemon -- an unused branch included -- makes the
    /// dynamic loader refuse the whole binary on Linux-PAM 1.3.1 (Ubuntu
    /// 20.04, RHEL 8) before `main` runs. A runtime field read by a
    /// non-test branch would defeat even the release build's inlining, so
    /// the field itself is gated and not only what reads it.
    /// `scripts/check-pam-linkage.sh` checks the result, in both profiles.
    #[cfg(test)]
    pub pam_confdir: Option<std::path::PathBuf>,
}

/// The PAM service the daemon opens every login's session for:
/// `/etc/pam.d/qshd`.
pub const PAM_SERVICE: &str = "qshd";

/// The group a channel's terminal is given to, by name. `tty` is the
/// conventional one -- what `sshd` and `login` leave a terminal in -- but it
/// is a convention, not a guarantee: see [`tty_group_named`].
const TTY_GROUP: &str = "tty";

impl HelperConfig {
    /// Resolve every setting the helper needs, once, before the fork.
    pub fn resolve(args: &ServeArgs) -> HelperConfig {
        HelperConfig::resolve_with_tty_group(args, TTY_GROUP)
    }

    /// [`HelperConfig::resolve`]'s whole body, with the terminal group's
    /// name as a parameter.
    ///
    /// Only so a test can drive THIS function -- the one the daemon
    /// actually starts with -- against a machine that has no such group,
    /// which is the case the `None` fallback exists for and which asking
    /// for `tty` on a machine that has one cannot produce. A test of
    /// `tty_group_named` alone would not notice a `resolve` that stopped
    /// consulting the group, or one that treated its absence as fatal.
    fn resolve_with_tty_group(args: &ServeArgs, tty_group: &str) -> HelperConfig {
        HelperConfig {
            authorized_keys_template: args.authorized_keys_template.clone(),
            permit_root: args.permit_root,
            tty_gid: tty_group_named(tty_group),
            worker_user: args.worker_user.clone(),
            startup_timeout: super::server::STARTUP_REPORT_TIMEOUT,
            verify_timeout: super::server::VERIFY_TIMEOUT,
            pam_service: PAM_SERVICE.to_string(),
            // The daemon reads `/etc/pam.d`, always: see the field.
            #[cfg(test)]
            pam_confdir: None,
        }
    }
}

/// Look up a group by name, treating absence as absence rather than as an
/// error: `tty` is conventional, not guaranteed -- a machine without one
/// simply gives a channel's terminal to the account's own group instead.
pub fn tty_group_named(name: &str) -> Option<Gid> {
    nix::unistd::Group::from_name(name)
        .ok()
        .flatten()
        .map(|g| g.gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ServeArgs` whose every helper-visible field is distinguishable
    /// from its default, so a `resolve` that dropped one on the floor shows.
    fn args() -> ServeArgs {
        ServeArgs {
            port: 60022,
            authorized_keys: None, // unread in the system mode -- see its own doc comment
            host_key: "/etc/qshd/host_key".into(),
            system: true,
            worker_user: "nobody".to_string(),
            permit_root: true,
            authorized_keys_template: "/etc/qshd/keys/%u".to_string(),
            runtime_threads: None,
        }
    }

    /// The tty group is looked up once, at startup, and its absence is not
    /// an error: a machine without one simply leaves the terminal in the
    /// account's own group. Driven through `HelperConfig::resolve`'s own
    /// body (with the group's name injected, since this machine does have a
    /// `tty` group) rather than through `tty_group_named` alone, so what is
    /// pinned is the config the helper actually starts with -- every other
    /// field included.
    #[test]
    fn a_missing_tty_group_is_not_fatal_and_costs_no_other_setting() {
        let config = HelperConfig::resolve_with_tty_group(&args(), "definitely-no-such-group");
        assert!(
            config.tty_gid.is_none(),
            "a group that does not exist must resolve to None, not fail the startup"
        );
        assert_eq!(config.authorized_keys_template, "/etc/qshd/keys/%u");
        assert!(config.permit_root);
        assert_eq!(config.worker_user, "nobody");
        assert_eq!(
            config.startup_timeout,
            super::super::server::STARTUP_REPORT_TIMEOUT,
            "the daemon's startup budget is the constant, not whatever a test happens to set"
        );
        assert_eq!(
            config.verify_timeout,
            super::super::server::VERIFY_TIMEOUT,
            "and so is the budget one client's proof gets before the helper gives up on it"
        );
        assert_eq!(
            config.pam_service, PAM_SERVICE,
            "the daemon opens every session for its own service, /etc/pam.d/qshd"
        );
        assert_eq!(
            config.pam_confdir, None,
            "and reads that stack from /etc/pam.d: nothing the daemon is started with may \
             redirect where a root process reads its policy from"
        );
    }

    /// And the name the production entry point asks for is the
    /// conventional one: whatever this machine's `tty` group resolves to is
    /// what `resolve` puts in the config.
    #[test]
    fn resolve_asks_for_the_conventional_tty_group() {
        assert_eq!(
            HelperConfig::resolve(&args()).tty_gid,
            tty_group_named("tty")
        );
    }
}
