//! The `serve` command: a long-lived daemon on a fixed UDP port that hands an
//! authenticated client channels, the way `sshd` does, rather than one fixed
//! product per connection ([`crate::channel_backend::ChannelSessionBackend`]).
//!
//! Unlike `transport-ensure`, nothing installs or bootstraps it over SSH: it
//! is started by the user (or by a service manager -- see
//! `docs/qshd-service.md`), it keeps a permanent host key, and it decides who
//! may come in by checking an SSH signature against `authorized_keys`.

use std::ffi::OsString;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sshauth::verify::AuthorizedKeysVerifier;
use transport::auth::Principal;
use transport::session_manager::{LoginEndedReports, ServerAuth};

use crate::channel_backend::ChannelSessionBackend;
use crate::{log, transport_daemon};

/// The UDP port `serve` listens on unless told otherwise.
pub const DEFAULT_SERVE_PORT: u16 = 60022;

/// What `serve` was asked to do.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServeArgs {
    pub port: u16,
    /// Where the personal mode's `AuthorizedKeysVerifier` looks -- `None`
    /// in, and only in, the system mode, which never reads a single shared
    /// file at all (`--authorized-keys` is refused outright for
    /// `--system`, above): each account's own is found through
    /// `authorized_keys_template` instead. Optional rather than a
    /// placeholder path so a system-mode `ServeArgs` cannot even represent
    /// a value nothing reads -- see `parse_serve_args`'s default for why
    /// that used to matter.
    pub authorized_keys: Option<PathBuf>,
    pub host_key: PathBuf,
    /// Run as the system daemon: before the tokio runtime exists, the
    /// process splits into a privileged helper and a worker that talk over
    /// a `socketpair` (see the `helper` module, built only with the
    /// `system` feature). Deliberately absent from the help text until it
    /// does what its name promises -- today it splits the processes and
    /// nothing more.
    pub system: bool,
    /// The unprivileged account the WORKER runs as once the split has
    /// happened. The helper stays privileged; the worker, which is the half
    /// that parses everything a stranger sends, must not be.
    pub worker_user: String,
    /// Whether a client may ask to log in as `uid 0`. Off by default: the
    /// daemon has no way to make that safer than it sounds.
    pub permit_root: bool,
    /// Where an account's authorized keys live. `%h` expands to the home
    /// directory from `passwd`, `%u` to the login name.
    pub authorized_keys_template: String,
}

/// `$HOME`, required. The default `authorized_keys`/host-key paths are
/// derived from it; silently falling back to the working directory (as an
/// earlier version of this function did) would put the host key's secrecy
/// at the mercy of wherever `serve` happens to be launched from -- worth
/// refusing outright instead. Only called when a default is actually
/// needed: a caller who passes both `--authorized-keys` and `--host-key`
/// explicitly never hits this, even with `HOME` unset.
fn home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        anyhow::anyhow!(
            "the HOME environment variable is not set -- specify --authorized-keys and --host-key explicitly"
        )
    })
}

/// Parse `serve`'s arguments (the first element is the subcommand itself).
pub fn parse_serve_args(args: &[String]) -> Result<ServeArgs> {
    parse_serve_args_os(&args.iter().map(OsString::from).collect::<Vec<_>>())
}

fn argument_text((index, value): (usize, &OsString)) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("argument {} must be valid UTF-8", index + 1))
}

/// Parse OS arguments without converting filesystem paths to text.
pub fn parse_serve_args_os(args: &[OsString]) -> Result<ServeArgs> {
    let mut port = None;
    let mut authorized_keys = None;
    let mut host_key = None;
    // Only mutated in the `#[cfg(feature = "system")]` arm below -- without
    // the feature the flag is refused outright, so `mut` goes unused there.
    #[cfg_attr(not(feature = "system"), allow(unused_mut))]
    let mut system = false;
    // These three, like `system` above, are only ever set inside a
    // `#[cfg(feature = "system")]` arm -- without the feature every flag
    // that would set one is refused outright before it can.
    #[cfg_attr(not(feature = "system"), allow(unused_mut))]
    let mut worker_user = None;
    #[cfg_attr(not(feature = "system"), allow(unused_mut))]
    let mut permit_root = false;
    #[cfg_attr(not(feature = "system"), allow(unused_mut))]
    let mut authorized_keys_template = None;
    let mut rest = args.iter().enumerate().skip(1);
    while let Some(flag) = rest.next() {
        let flag = argument_text(flag)?;
        let mut value = || {
            rest.next()
                .ok_or_else(|| anyhow::anyhow!("flag {flag} needs a value"))
        };
        match flag {
            "--port" => {
                let parsed_port: u16 = argument_text(value()?)?
                    .parse()
                    .context("port must be a number 1..65535")?;
                if parsed_port == 0 {
                    bail!("port must be a number 1..65535, got 0");
                }
                port = Some(parsed_port);
            }
            "--authorized-keys" => authorized_keys = Some(PathBuf::from(value()?.1)),
            "--host-key" => host_key = Some(PathBuf::from(value()?.1)),
            "--system" => {
                #[cfg(feature = "system")]
                {
                    system = true;
                }
                #[cfg(not(feature = "system"))]
                {
                    bail!(
                        "this binary was built without the system mode; rebuild with \
                         `cargo build --features system`"
                    );
                }
            }
            "--worker-user" => {
                #[cfg(feature = "system")]
                {
                    worker_user = Some(argument_text(value()?)?.to_owned());
                }
                #[cfg(not(feature = "system"))]
                {
                    bail!(
                        "this binary was built without the system mode; rebuild with \
                         `cargo build --features system`"
                    );
                }
            }
            "--permit-root" => {
                #[cfg(feature = "system")]
                {
                    permit_root = true;
                }
                #[cfg(not(feature = "system"))]
                {
                    bail!(
                        "this binary was built without the system mode; rebuild with \
                         `cargo build --features system`"
                    );
                }
            }
            "--authorized-keys-template" => {
                #[cfg(feature = "system")]
                {
                    authorized_keys_template = Some(argument_text(value()?)?.to_owned());
                }
                #[cfg(not(feature = "system"))]
                {
                    bail!(
                        "this binary was built without the system mode; rebuild with \
                         `cargo build --features system`"
                    );
                }
            }
            other => bail!("unknown flag {other}"),
        }
    }
    // A single file cannot serve many accounts, and silently reinterpreting
    // the flag would be worse than refusing it.
    if system && authorized_keys.is_some() {
        bail!(
            "--authorized-keys names a single file and cannot serve several accounts; \
             use --authorized-keys-template (%h expands to the home directory, %u to the \
             login name)"
        );
    }
    // The template flag belongs to the system mode; in the personal mode
    // there is one account and nothing to expand.
    if !system && authorized_keys_template.is_some() {
        bail!("--authorized-keys-template applies to --system only");
    }

    let authorized_keys = match authorized_keys {
        Some(p) => Some(p),
        // Symmetric to `host_key` below: the system mode never reads this
        // field at all (its helper reads each account's own file, named by
        // `--authorized-keys-template`), so there is no default worth
        // deriving from `$HOME` for it -- and `$HOME` is exactly what
        // `systemd` sets none of for a system-level service. Deriving one
        // anyway used to fail every system-mode start on `$HOME` alone,
        // for a value the mode goes on to ignore.
        None if system => None,
        None => Some(home()?.join(".ssh").join("authorized_keys")),
    };
    let host_key = match host_key {
        Some(p) => p,
        // The system daemon's key identifies the MACHINE, not one person's
        // account, so it does not live in anybody's home directory.
        None if system => PathBuf::from("/etc/qshd/host_key"),
        None => home()?.join(".config").join("qshd").join("host_key"),
    };
    let worker_user = worker_user.unwrap_or_else(|| "qshd".to_string());
    let authorized_keys_template =
        authorized_keys_template.unwrap_or_else(|| "%h/.ssh/authorized_keys".to_string());
    Ok(ServeArgs {
        port: port.unwrap_or(DEFAULT_SERVE_PORT),
        authorized_keys,
        host_key,
        system,
        worker_user,
        permit_root,
        authorized_keys_template,
    })
}

/// Where the system mode's diagnostic file log lives -- see [`cache_dir`]
/// for why it is a fixed path and not one derived from an account's `$HOME`.
///
/// Public because the integration suites read this log to find out WHICH
/// check refused a login (the wire only ever carries a fixed reason), and a
/// second copy of the path in the tests is a second source of truth for it.
/// That shape has already cost this slice once: a refusal guarded the PAM
/// service name as a literal while the code that opened it used the
/// constant, so a rename would have silently reopened the hole.
///
/// `serve`'s own `the_system_mode_log_directory_ignores_home` still writes
/// the literal out, deliberately: a test that compared this constant with
/// itself would pass whatever the constant said.
pub const SYSTEM_LOG_DIR: &str = "/var/log/qshd";

/// The directory for the diagnostic file log ([`crate::log`]) -- the same
/// `qshd.log` every other `qshd` subcommand writes to in the personal mode.
/// `serve` does not fork, so its stdout/stderr are whatever the caller (a
/// terminal, or a service manager) makes of them; the file log is a second,
/// platform-independent way to find the startup fingerprint and later
/// diagnostics regardless of how (or whether) the service manager captured
/// them. [`log::init`] creates this directory if it does not exist yet --
/// unlike the `transport-*` commands, `serve`'s host key lives elsewhere,
/// so nothing else creates it first.
///
/// The personal mode's directory (honours `$XDG_CACHE_HOME` on Linux, via
/// `dirs::cache_dir()`) is unchanged. The system mode does NOT reach
/// `dirs::cache_dir()` at all: that function derives from `$HOME` --
/// `systemd` sets none for a system-level service, same as `authorized_keys`'
/// default above -- and even where `$HOME` is unset, `dirs::cache_dir()`
/// falls back to `getpwuid_r` (see `dirs_sys::home_dir`), which resolves to
/// SOME account's home directory rather than failing cleanly: `/root` under
/// a plain `systemctl enable --now`, but genuinely whichever account the
/// unit's `User=` names. That is the single-personal-path shape design 7.2
/// exists to reject, arrived at through a different door than
/// `Environment=HOME=` -- so the system mode gets a directory that does not
/// move with the account at all. `/var/log` is where FHS puts a service's
/// own diagnostics, which is what this file is; a service log is not a
/// per-user cache in the first place, in the personal mode either, but that
/// mismatch is not this task's to fix.
fn cache_dir(system: bool) -> PathBuf {
    if system {
        return PathBuf::from(SYSTEM_LOG_DIR);
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("qsh")
}

/// Checks the host key file's permissions and tightens them to `0600` if
/// they are wider (readable/writable by group or other). `serve`'s host key
/// is not a cache-directory key living as long as one `transport-ensure`
/// login -- it is the permanent identity of an unattended service, and the
/// whole first-contact trust model (`docs/qshd-service.md`) rests on it
/// staying secret. `load_or_create_transport_key` already creates it with
/// `0600` (atomically, no umask-readable window), but that only covers
/// CREATION: a file that already existed with looser permissions (copied in
/// by hand, restored from a backup, ...) is loaded as-is. Tightening does
/// NOT undo a past leak, so a loose mode is warned about loudly (through the
/// same channel as every other startup warning here) rather than silently
/// repaired -- but the daemon still starts: refusing to start over a
/// permissions problem it can fix itself would be a worse failure than
/// starting, repairing, and complaining (unlike OpenSSH's hard refusal for
/// private keys, which this deliberately does not copy).
#[cfg(unix)]
fn tighten_host_key_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o777,
        // Already loaded successfully by the caller -- a `stat` failing
        // right after that would be bizarre, but this check is not worth
        // failing startup over either way.
        Err(_) => return,
    };
    if mode & 0o077 == 0 {
        return;
    }
    let warning = format!(
        "host key {} was accessible to more than the owner (mode {mode:03o}) -- \
         permissions fixed to 0600, but this does not undo a possible past leak; if you are \
         not sure nobody else had access to the file, it is safer to delete it and restart the \
         daemon -- a new host key will be created",
        path.display()
    );
    // To the file and, `serve` mirroring every line, to stderr -- which
    // `log` writes without `eprintln!`, so a closed stderr cannot turn this
    // warning into a panic before the daemon ever binds.
    log::warn("qshd", &warning);
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn tighten_host_key_permissions(_path: &Path) {}

/// The personal mode serves the account that starts it. As root that
/// would mean every session running as root, with no PAM stack and no
/// account check anywhere -- the system mode's job, done without any of
/// the system mode's care. Refuse, and name `--system`, because a unit
/// that forgot the flag is by far the likeliest way to get here.
///
/// Taking the uid as an argument rather than reading it makes this
/// testable without being root; the caller passes the real one.
fn refuse_personal_mode_as_root(uid: nix::unistd::Uid) -> anyhow::Result<()> {
    if uid.is_root() {
        anyhow::bail!(
            "the personal mode refuses to run as root: it serves the account that starts \
             it, so as root every session would run as root with no PAM stack and no \
             account check. Did you mean `qshd serve --system`?"
        );
    }
    Ok(())
}

/// Refuse to start when our own PAM service file is missing while the
/// directory that would hold it exists.
///
/// Without `/etc/pam.d/qshd`, Linux-PAM falls through to
/// `/etc/pam.d/other`, and what that does is a property of the
/// distribution rather than of our design: Debian's admits (and on a
/// machine whose `other` is `pam_permit`, admits an EXPIRED account
/// without writing a line), Fedora's denies everyone. Neither is our
/// decision to inherit, so a packaging slip must stop the daemon rather
/// than silently change who may log in.
///
/// The directory check is not defensive clutter: a machine using a single
/// `/etc/pam.conf` has no `/etc/pam.d` at all, and refusing there would be
/// this daemon's assumption speaking rather than the machine's state.
#[cfg(feature = "system")]
fn refuse_without_pam_service(pam_d: &Path, service: &str) -> anyhow::Result<()> {
    if !pam_d.is_dir() {
        return Ok(());
    }
    let file = pam_d.join(service);
    if file.exists() {
        return Ok(());
    }
    anyhow::bail!(
        "the system mode needs its own PAM service file: {} is missing while {} exists. \
         Without it PAM falls through to `other`, which admits on some distributions and \
         refuses everyone on others -- neither is a decision this daemon may inherit. \
         Install the qshd package, or copy packaging/pam.d/qshd.debian (or .fedora) there.",
        file.display(),
        pam_d.display()
    )
}

/// Run the daemon in the foreground: a service manager owns the process, so
/// there is nothing to daemonize here (`transport-ensure` forks because an
/// SSH login must return; `serve` is started by systemd or launchd, which
/// expect to keep the process).
pub fn run_serve_command(args: &[String]) -> Result<()> {
    run_serve_command_os(&args.iter().map(OsString::from).collect::<Vec<_>>())
}

/// OS-aware entrypoint; parsing still precedes all startup side effects.
pub fn run_serve_command_os(args: &[OsString]) -> Result<()> {
    let parsed = parse_serve_args_os(args)?;

    // First, before this process opens a single descriptor of its own: in
    // the system mode the helper's channels rely on 0, 1 and 2 being taken
    // -- see `helper::ensure_standard_descriptors` for why.
    //
    // The three refusals that can stop the system mode outright follow
    // immediately, and BEFORE anything is created, written or bound: a
    // start that is going to be refused must not first create
    // `/etc/qshd/host_key` -- the machine's permanent identity -- or take
    // the port. All three are decisions about this process alone or about
    // files already on the machine, needing no descriptor of our own, so
    // nothing has to happen before them.
    #[cfg(feature = "system")]
    if parsed.system {
        crate::helper::ensure_standard_descriptors()
            .context("making sure descriptors 0, 1 and 2 are open")?;

        // The helper must be able to become any account; without that the
        // mode cannot do what its name says, and failing here is far kinder
        // than failing at the first login.
        if !nix::unistd::Uid::effective().is_root() {
            anyhow::bail!(
                "the system mode needs to start with privileges: the helper becomes each \
                 account it serves. Run it from a service manager as root, or use the \
                 personal mode (`qshd serve` without --system), which serves the account \
                 that starts it"
            );
        }

        // A securebit that would keep root's capabilities across a channel's
        // `setuid` makes the whole privilege model a lie -- refuse to start
        // with a message the operator can act on, rather than fail every
        // login. See `helper::refuse_dangerous_securebits`.
        crate::helper::refuse_dangerous_securebits()?;

        // The last of the three refusals that stop the system mode before
        // anything is created or bound. See `refuse_without_pam_service`
        // for why a missing service file is not a harmless omission.
        //
        // `crate::helper::config::PAM_SERVICE`, not a literal "qshd": that
        // constant is the one thing every PAM caller in the daemon opens,
        // so this refusal guards the very file the daemon reads rather
        // than a name that happens to match it today.
        refuse_without_pam_service(Path::new("/etc/pam.d"), crate::helper::config::PAM_SERVICE)?;
    }

    // The personal mode's own refusal, symmetric to the system mode's two
    // above and in the same place: before a host key is created or a port
    // is taken. It is not behind the `system` feature -- a build without
    // the feature has only this mode, and that is exactly the build most
    // likely to be started by a unit that meant to say `--system`.
    if !parsed.system {
        refuse_personal_mode_as_root(nix::unistd::Uid::effective())?;
    }

    // The file log works even when the service manager discards stdout/stderr
    // (launchd does, unless the unit sets `StandardOutPath`/`StandardErrorPath`
    // -- see `docs/qshd-service.md`), so the fingerprint below and any later
    // session-lifecycle notices (the `transport` crate's `log` records) always
    // land somewhere an operator can read after the fact.
    //
    // And every line goes to stderr as well, for the journal: authentication
    // rejections included -- `probation.rs` logs "session refused: ..." --
    // which is the audit trail `docs/qshd-service.md` tells the operator to
    // watch for in `journalctl`. Set before `init`, and before the system
    // mode forks, so the helper and the worker mirror their lines too.
    log::mirror_to_stderr();
    log::init(&cache_dir(parsed.system));

    let keypair = crate::load_or_create_transport_key(&parsed.host_key)
        .with_context(|| format!("host key {}", parsed.host_key.display()))?;
    tighten_host_key_permissions(&parsed.host_key);

    // Nothing about `authorized_keys` is fatal here: `AuthorizedKeysVerifier`
    // re-reads the file on every attempt, so an operator may deliberately
    // start the daemon before populating it. But a missing file means every
    // client is refused until it exists, and that is worth saying loudly at
    // startup rather than only as a per-attempt "reading ...: No such file or
    // directory" once someone tries to connect. `None` only in the system
    // mode, which never reads this file at all -- its helper reads each
    // account's own, named by `--authorized-keys-template` -- so the `if let`
    // alone is enough of a guard; no separate `!parsed.system` needed.
    if let Some(authorized_keys) = &parsed.authorized_keys {
        if !authorized_keys.exists() {
            let warning = format!(
                "authorized_keys file {} not found -- nobody will be able to \
                 connect yet; add the client's public key to it in authorized_keys format \
                 (see docs/qshd-service.md)",
                authorized_keys.display()
            );
            // To the file and to stderr, as the host key's warning above.
            log::warn("qshd", &warning);
        }
    }

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, parsed.port))
        .with_context(|| format!("binding UDP port {}", parsed.port))?;

    // The fingerprint is what a user compares against on their first
    // connection -- printed on stdout (alongside `server-pubkey`, a
    // different encoding of the same key) so the trust model's starting
    // point is available even if the file log somehow isn't, and written to
    // the log for later reference.
    let fingerprint = sshauth::known_hosts::key_fingerprint(&keypair.public);
    // What decides who gets in, for the log: one file in the personal mode,
    // each account's own file -- named by the template -- in the system
    // mode.
    let keys = match &parsed.authorized_keys {
        Some(path) => format!("authorized_keys {}", path.display()),
        None => format!(
            "authorized_keys_template {}",
            parsed.authorized_keys_template
        ),
    };
    log::info(
        "qshd",
        &format!("port {} key {fingerprint} {keys}", parsed.port),
    );
    println!("server-pubkey: {}", BASE64.encode(keypair.public));
    println!("host-key-fingerprint: {fingerprint}");

    #[cfg(feature = "system")]
    if parsed.system {
        // The root requirement and the securebits refusal already ran, at
        // the top of this function: both are refusals, and a refused start
        // must not have created the host key or bound the port first.

        // Resolved once, here, before the split: the privileged helper must
        // not go back to the database (a group lookup, among other things)
        // on every channel a client asks for.
        let helper_config = crate::helper::HelperConfig::resolve(&parsed);
        let worker_user = parsed.worker_user.clone();

        // `utf8_locale_env` runs `locale -a`, through a `PATH` search, the
        // first time it is asked -- and that must never happen in the
        // helper, as root, on demand, because a client asked for a channel.
        // Asked once here instead, in the one process there is before the
        // split: the answer is memoized (a `OnceLock`), the fork copies it
        // into both halves, and the helper's channels only ever read it.
        let _ = crate::pty::utf8_locale_env();

        // The UDP socket is bound BEFORE the split so a port below 1024
        // would still be bindable, and so a port already in use fails the
        // service at once rather than after a process tree exists.
        return crate::helper::split_and_run(
            helper_config,
            move |spawner, helper_auth, login_ends| {
                // Built HERE, in the worker, after the split -- unlike the
                // personal mode's, below: the helper-backed source of nonces and
                // verdicts exists only on this side of the fork. The pool, above
                // all, can exist nowhere else: it starts a thread, and
                // `split_and_run` refuses to fork a process that has more than
                // one. It draws from the one helper client there is, and fills
                // itself before the runtime below exists.
                let helper_auth = Arc::new(helper_auth);
                let nonces = crate::nonce_pool::PooledNonces::start(Arc::clone(&helper_auth))
                    .context("starting the nonce pool")?;
                // A fresh allowlist that nothing else holds: see
                // `refuse_the_allowlist_path` for why both halves matter.
                let auth = system_server_auth(
                    keypair.public,
                    helper_auth,
                    nonces,
                    &worker_user,
                    Arc::new(Mutex::new(Vec::new())),
                )?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .context("creating the tokio runtime")?;
                runtime.block_on(transport_daemon::run_serve_loop(
                    socket,
                    keypair.private,
                    auth,
                    Arc::new(managed(ChannelSessionBackend::with_spawner(Arc::new(
                        spawner,
                    )))),
                    // The helper's own reports that a login has ended -- the
                    // one thing that can tell this router a session has gone
                    // sterile. See `transport::LoginEndedReporter`.
                    login_ends,
                ))
            },
        );
    }

    // The account this daemon serves -- it runs as exactly one. The name is
    // a log label only (nothing selects an account here), so the
    // environment is a good enough source and keeps the static musl build
    // free of an NSS lookup.
    let uid = nix::unistd::Uid::current().as_raw();
    let name = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| uid.to_string());

    let auth = ServerAuth {
        // Nothing is bootstrapped over SSH here, so the allowlist starts (and
        // stays) empty: every client proves itself with a signature.
        allowlist: Arc::new(Mutex::new(Vec::new())),
        verifier: Some(Arc::new(AuthorizedKeysVerifier::new(
            // Only reachable here in the personal mode: the system mode's
            // branch, above, already returned. `parse_serve_args` sets this
            // field for every personal-mode `ServeArgs`, so this is not a
            // production possibility -- see its doc comment.
            parsed
                .authorized_keys
                .clone()
                .expect("the personal mode always sets authorized_keys"),
            uid,
            name.clone(),
        ))),
        server_pub: keypair.public,
        // The allowlist path has no verifier to ask, so it is proven by its
        // static key alone: a session bound that way runs as this daemon's
        // own account. Never reached in practice here -- `serve`'s allowlist
        // stays empty -- but the field is required all the same.
        self_principal: Principal {
            uid,
            name,
            identity: "allowlist".to_string(),
            incarnation: 0,
        },
        // Minted locally: there is no helper in the personal mode, and no
        // other account for a nonce to be kept from.
        nonces: Arc::new(crate::RandomNonces),
        // One login, no PAM session, nothing else keyed by a login -- see
        // `ForgetNothing`'s own docs.
        logins: Arc::new(crate::ForgetNothing),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating the tokio runtime")?;
    runtime.block_on(transport_daemon::run_serve_loop(
        socket,
        keypair.private,
        auth,
        Arc::new(managed(ChannelSessionBackend::new())),
        // No helper, so nobody can report a login ended from outside: in
        // the personal mode the router is the only authority on whether a
        // login lives.
        LoginEndedReports::none(),
    ))
}

/// A `serve` daemon describes itself but never replaces itself: a service
/// manager started it, from a path a package or an administrator owns. Its
/// own checksum is worked out on the first `About`, not here.
fn managed(backend: ChannelSessionBackend) -> ChannelSessionBackend {
    backend.with_daemon(Arc::new(crate::update::DaemonSelf::managed(None)))
}

/// The system mode's authentication setup, built inside the worker after
/// the split.
///
/// Every nonce, every verdict and every login-ended notice goes through the
/// helper, through ONE [`HelperAuth`](crate::helper::spawner::HelperAuth) --
/// one seam, one lock, one numbering. Verdicts and login-ended notices go to
/// it directly; nonces come from `nonces`, the pool that draws from it,
/// because the router asks for a nonce on the task that routes every session
/// and must never wait for the helper there. The parameter is the pool's own
/// type: the helper client itself is not a `NonceSource` at all, and a
/// source that mints nonces in the worker cannot be handed in either. There
/// is no `AuthorizedKeysVerifier` here at all: the worker has no right to
/// read another account's files, and should hold no code that tries.
///
/// `allowlist` comes from the caller -- production passes a fresh, empty
/// one -- so that a test can hand in one that is not, and see this very
/// function refuse it: the check is part of building the system mode's
/// setup, not a separate step a caller could forget.
#[cfg(feature = "system")]
fn system_server_auth(
    server_pub: [u8; 32],
    helper: Arc<crate::helper::spawner::HelperAuth>,
    nonces: Arc<crate::nonce_pool::PooledNonces>,
    worker_user: &str,
    allowlist: transport::session_manager::SharedAllowlist,
) -> Result<ServerAuth> {
    let auth = ServerAuth {
        // Refused below unless it is empty and nobody else holds it -- see
        // `refuse_the_allowlist_path`.
        allowlist,
        verifier: Some(helper.clone()),
        server_pub,
        // The allowlist path's principal: this process's own account, which
        // after the split is the worker's, not root. The path is refused
        // outright below, so nothing ever uses this value; of the accounts
        // it could name, it is the least dangerous to hold regardless.
        self_principal: Principal {
            uid: nix::unistd::Uid::current().as_raw(),
            name: worker_user.to_string(),
            identity: "allowlist".to_string(),
            incarnation: 0,
        },
        nonces,
        logins: helper,
    };
    refuse_the_allowlist_path(&auth)?;
    Ok(auth)
}

/// Refuses to start the system mode with anything in the allowlist.
///
/// The allowlist path has no verifier -- a static key is its own proof -- so
/// whoever logs in by it becomes `ServerAuth::self_principal`, the daemon's
/// own account, without the helper ever checking anything. In the personal
/// mode that is the point: that daemon serves exactly one account. In the
/// system mode it would be a door around the helper, and on a machine the
/// daemon starts on as root, a door into the daemon account's sessions for
/// every listed key. `serve` never populates the allowlist, so the path is
/// unreachable today; this asserts that rather than trusting it, because a
/// future caller that did populate it would open that door silently.
///
/// Empty is not enough on its own: this runs once, at startup, and cannot
/// see a key added later. So the list must also be held by nothing but this
/// `ServerAuth` at the moment of the check -- a second holder is a second
/// way for a key to arrive after it. What the count cannot see is a clone
/// taken LATER: `transport-ensure` builds its control socket (which adds
/// keys live) after its `ServerAuth` already exists, and a check standing
/// here could never have observed that. This is a guard for the shape the
/// SYSTEM mode builds -- one fresh list, handed straight to this function
/// and to nothing else -- not a proof about every possible caller.
#[cfg(feature = "system")]
fn refuse_the_allowlist_path(auth: &ServerAuth) -> Result<()> {
    let holders = Arc::strong_count(&auth.allowlist);
    if holders != 1 {
        bail!(
            "the system mode cannot serve the allowlist path, and its allowlist is shared \
             ({holders} holders): whoever else holds it could add keys after this check"
        );
    }
    // A list behind a lock some panic poisoned is still a list worth
    // checking.
    let listed = auth
        .allowlist
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len();
    if listed != 0 {
        bail!(
            "the system mode cannot serve the allowlist path: it has no verifier, so every \
             listed key would own the daemon account's sessions ({listed} listed)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn serve_os_paths_preserve_bytes_and_existing_option_boundaries() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        for value in [
            OsString::from_vec(b"path-\xff".to_vec()),
            "--help".into(),
            "--".into(),
        ] {
            let parsed = parse_serve_args_os(&[
                "serve".into(),
                "--host-key".into(),
                value.clone(),
                "--authorized-keys".into(),
                value.clone(),
            ])
            .unwrap();
            assert_eq!(parsed.host_key, PathBuf::from(&value));
            assert_eq!(parsed.authorized_keys, Some(PathBuf::from(value)));
        }
        for flag in ["--host-key", "--authorized-keys"] {
            assert_eq!(
                parse_serve_args_os(&["serve".into(), flag.into()])
                    .unwrap_err()
                    .to_string(),
                format!("flag {flag} needs a value")
            );
        }
        for trailing in [vec![], vec![OsString::from_vec(vec![0xff])]] {
            let mut argv = vec!["serve".into(), "--".into()];
            argv.extend(trailing);
            assert_eq!(
                parse_serve_args_os(&argv).unwrap_err().to_string(),
                "unknown flag --"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn serve_text_values_and_flags_require_utf8_without_weakening_feature_checks() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let invalid = OsString::from_vec(vec![0xff]);
        assert_eq!(
            parse_serve_args_os(&["serve".into(), invalid.clone()])
                .unwrap_err()
                .to_string(),
            "argument 2 must be valid UTF-8"
        );
        for flag in ["--port", "--worker-user", "--authorized-keys-template"] {
            let error =
                parse_serve_args_os(&["serve".into(), flag.into(), invalid.clone()]).unwrap_err();
            if flag != "--port" && !cfg!(feature = "system") {
                assert!(error.to_string().contains("built without the system mode"));
            } else {
                assert_eq!(error.to_string(), "argument 3 must be valid UTF-8");
            }
        }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let parsed = parse_serve_args(&args(&["serve"])).expect("parse");
        assert_eq!(parsed.port, DEFAULT_SERVE_PORT);
        assert!(parsed
            .authorized_keys
            .as_deref()
            .is_some_and(|p| p.ends_with(".ssh/authorized_keys")));
        assert!(parsed.host_key.ends_with(".config/qshd/host_key"));
    }

    #[test]
    fn every_flag_is_honoured() {
        let parsed = parse_serve_args(&args(&[
            "serve",
            "--port",
            "1234",
            "--authorized-keys",
            "/tmp/ak",
            "--host-key",
            "/tmp/hk",
        ]))
        .expect("parse");
        assert_eq!(parsed.port, 1234);
        assert_eq!(parsed.authorized_keys, Some(PathBuf::from("/tmp/ak")));
        assert_eq!(parsed.host_key, PathBuf::from("/tmp/hk"));
    }

    #[test]
    fn a_bad_port_and_an_unknown_flag_are_refused() {
        assert!(parse_serve_args(&args(&["serve", "--port", "no"])).is_err());
        assert!(parse_serve_args(&args(&["serve", "--port"])).is_err());
        assert!(parse_serve_args(&args(&["serve", "--wat"])).is_err());
    }

    /// The error text for a bad `--port` value promises "1..65535" -- `0`
    /// parses fine as a `u16` but is not in that range (it means "bind an
    /// ephemeral port" to the OS, which is never what a long-lived, fixed-
    /// address service wants), so it must be refused the same way a
    /// non-numeric value is.
    #[test]
    fn port_zero_is_refused() {
        assert!(parse_serve_args(&args(&["serve", "--port", "0"])).is_err());
    }

    /// A host key file that already exists with permissions wider than
    /// `0600` (e.g. copied in by hand) must be tightened in place -- this is
    /// the permanent identity of an unattended service, not a short-lived
    /// cache-directory key.
    #[cfg(unix)]
    #[test]
    fn a_wide_open_host_key_is_tightened_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host_key");
        std::fs::write(&path, [0u8; 64]).expect("write key bytes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set wide permissions");

        tighten_host_key_permissions(&path);

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "wide permissions must be tightened to 0600");
    }

    /// The personal mode refuses to start as root. Its whole shape is "serve
    /// the account that started me": as root that would mean every session
    /// running as root with no PAM and no account check at all, and the only
    /// way to arrive there on purpose is `--system`, which this is not.
    ///
    /// The refusal names the flag, because the overwhelmingly likely cause is
    /// a service unit that forgot it.
    #[test]
    fn the_personal_mode_refuses_to_start_as_root() {
        let refusal = refuse_personal_mode_as_root(nix::unistd::Uid::from_raw(0))
            .expect_err("uid 0 must be refused");
        let text = refusal.to_string();
        assert!(
            text.contains("--system"),
            "the refusal must name the flag whose absence is the likely cause, got {text:?}"
        );
        assert!(
            refuse_personal_mode_as_root(nix::unistd::Uid::from_raw(1000)).is_ok(),
            "an ordinary account must be free to run the personal mode"
        );
    }

    /// Without the feature there is no such flag at all, and saying it is an
    /// error rather than a silent no-op: a user who typed it expects the mode.
    #[cfg(not(feature = "system"))]
    #[test]
    fn the_system_flag_is_refused_in_a_build_without_it() {
        let err = parse_serve_args(&args(&["serve", "--system"])).expect_err("must refuse");
        assert!(
            err.to_string().contains("built without the system mode"),
            "the error must say the binary lacks the mode, got: {err}"
        );
    }

    #[cfg(feature = "system")]
    #[test]
    fn the_system_flag_is_accepted_and_moves_the_host_key() {
        let parsed = parse_serve_args(&args(&["serve", "--system"])).expect("parse");
        assert!(parsed.system);
        assert_eq!(parsed.host_key, PathBuf::from("/etc/qshd/host_key"));
    }

    /// Restores a set of environment variables to whatever they were before
    /// a test that changed them, even if that test's own assertion panics:
    /// `--test-threads=1` runs each such test alone, but every OTHER test in
    /// the same process still runs afterwards and shares this same
    /// environment -- and more than one of them (`defaults_are_the_documented_ones`,
    /// for one) reads `$HOME`.
    struct RestoreEnvVars(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl RestoreEnvVars {
        /// Removes every named variable, remembering what each held so
        /// `Drop` can put it back.
        fn unset(names: &[&'static str]) -> Self {
            let saved = names
                .iter()
                .map(|&name| {
                    let previous = std::env::var_os(name);
                    std::env::remove_var(name);
                    (name, previous)
                })
                .collect();
            RestoreEnvVars(saved)
        }
    }

    impl Drop for RestoreEnvVars {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    /// `systemd` sets no `$HOME` for a system-level service (see
    /// `docs/qshd-service.md`) -- exactly the environment `--system` starts
    /// in on a real machine, and the one a container running the packaged
    /// unit demonstrated crash-looping in. Parsing must still succeed: the
    /// personal mode's `authorized_keys` default is the ONLY thing that
    /// reads `$HOME` here, and the system mode never reads that field
    /// (`--authorized-keys` is refused outright for `--system`, in favour
    /// of `--authorized-keys-template`), so its absence must not be able to
    /// fail a system-mode parse. The assertion is not "does not panic" --
    /// it is the same shape as `the_system_flag_is_accepted_and_moves_the_host_key`
    /// above: parsing succeeded AND the rest of the struct came out right,
    /// proving the unused field was skipped rather than the whole parse
    /// short-circuited some other way.
    #[cfg(feature = "system")]
    #[test]
    fn the_system_mode_parses_without_home() {
        let _restore = RestoreEnvVars::unset(&["HOME"]);

        let parsed = parse_serve_args(&args(&["serve", "--system"])).expect(
            "the system mode must parse with no $HOME set: the personal mode's \
             authorized_keys default is the only thing that reads it, and the system mode \
             never uses that field",
        );
        assert!(parsed.system);
        assert_eq!(parsed.host_key, PathBuf::from("/etc/qshd/host_key"));
        // The field itself, not just the parse: `None` here is what proves
        // it was skipped rather than defaulted to some other value that
        // happened not to need `$HOME`.
        assert!(parsed.authorized_keys.is_none());
    }

    /// The second, non-crashing finding: `cache_dir()`, used only for the
    /// diagnostic file log, must not depend on `$HOME` in the system mode --
    /// the same mistake `authorized_keys`' default made above, just without
    /// a crash to notice it by. `dirs::cache_dir()` falls back to
    /// `getpwuid_r` when `$HOME` is unset (see `dirs_sys::home_dir`), so an
    /// UNSET `$HOME` does not reliably prove this: on a real account's own
    /// machine that fallback resolves to that account's own real, absolute
    /// home directory, and a naive "is the result absolute" assertion
    /// passes by accident -- for a reason that has nothing to do with
    /// whether the system mode is right. (An earlier version of this test
    /// did exactly that, silently, against whichever account ran it.) A
    /// DECOY `$HOME` sidesteps the fallback entirely: if `cache_dir(true)`
    /// followed it at all, the decoy would show up in the result.
    #[test]
    fn the_system_mode_log_directory_ignores_home() {
        // `XDG_CACHE_HOME` unset too: `dirs::cache_dir()` prefers it over
        // `$HOME`, and it must play no part in the system mode either.
        let _restore = RestoreEnvVars::unset(&["HOME", "XDG_CACHE_HOME"]);
        std::env::set_var("HOME", "/tmp/qshd-test-decoy-home");
        assert_eq!(
            cache_dir(true),
            PathBuf::from("/var/log/qshd"),
            "the system mode's log directory must be fixed, not tied to whichever \
             account's $HOME happens to be set"
        );
    }

    /// The personal mode is unchanged: it still follows `$HOME` (through
    /// `dirs::cache_dir()`), exactly as before this task.
    #[test]
    fn the_personal_mode_log_directory_still_follows_home() {
        let _restore = RestoreEnvVars::unset(&["HOME", "XDG_CACHE_HOME"]);
        std::env::set_var("HOME", "/tmp/qshd-test-decoy-home");
        assert_eq!(
            cache_dir(false),
            PathBuf::from("/tmp/qshd-test-decoy-home/.cache/qsh")
        );
    }

    /// An explicit --host-key still wins in the system mode.
    #[cfg(feature = "system")]
    #[test]
    fn an_explicit_host_key_survives_the_system_mode() {
        let parsed = parse_serve_args(&args(&["serve", "--system", "--host-key", "/tmp/hk"]))
            .expect("parse");
        assert_eq!(parsed.host_key, PathBuf::from("/tmp/hk"));
    }

    /// Without the flag nothing moves: the personal mode is untouched.
    #[test]
    fn without_the_flag_the_host_key_stays_in_the_home_directory() {
        let parsed = parse_serve_args(&args(&["serve"])).expect("parse");
        assert!(parsed.host_key.ends_with(".config/qshd/host_key"));
    }

    #[cfg(feature = "system")]
    #[test]
    fn the_system_mode_has_its_own_defaults() {
        let parsed = parse_serve_args(&args(&["serve", "--system"])).expect("parse");
        assert_eq!(parsed.worker_user, "qshd");
        assert!(!parsed.permit_root);
        assert_eq!(parsed.authorized_keys_template, "%h/.ssh/authorized_keys");
    }

    /// A single file cannot serve many accounts, and silently reinterpreting the
    /// flag would be worse than refusing it.
    #[cfg(feature = "system")]
    #[test]
    fn authorized_keys_is_refused_in_the_system_mode() {
        let err = parse_serve_args(&args(&[
            "serve",
            "--system",
            "--authorized-keys",
            "/tmp/ak",
        ]))
        .expect_err("must refuse");
        assert!(
            err.to_string().contains("--authorized-keys-template"),
            "the error must name the flag to use instead, got: {err}"
        );
    }

    #[cfg(feature = "system")]
    #[test]
    fn the_template_and_the_worker_account_are_settable() {
        let parsed = parse_serve_args(&args(&[
            "serve",
            "--system",
            "--authorized-keys-template",
            "/etc/qshd/keys/%u",
            "--worker-user",
            "nobody",
            "--permit-root",
        ]))
        .expect("parse");
        assert_eq!(parsed.authorized_keys_template, "/etc/qshd/keys/%u");
        assert_eq!(parsed.worker_user, "nobody");
        assert!(parsed.permit_root);
    }

    /// The template flag belongs to the system mode; in the personal mode there
    /// is one account and nothing to expand.
    #[test]
    fn the_template_is_refused_without_the_system_mode() {
        assert!(parse_serve_args(&args(&["serve", "--authorized-keys-template", "%h/x"])).is_err());
    }

    /// The system mode refuses to start with anything in the allowlist: that
    /// path has no verifier, so every listed key would own the daemon
    /// account's sessions without the helper ever checking a thing. The
    /// empty list the system mode actually builds is the positive control --
    /// the refusal is about what is in the list, not about the list existing.
    #[cfg(feature = "system")]
    #[test]
    fn the_system_mode_refuses_a_populated_allowlist() {
        let auth_with = |allowlist: Vec<[u8; 32]>| ServerAuth {
            allowlist: Arc::new(Mutex::new(allowlist)),
            verifier: None,
            server_pub: [0u8; 32],
            self_principal: Principal {
                uid: 0,
                name: "root".to_string(),
                identity: "allowlist".to_string(),
                incarnation: 0,
            },
            nonces: Arc::new(crate::RandomNonces),
            logins: Arc::new(crate::ForgetNothing),
        };
        assert!(
            refuse_the_allowlist_path(&auth_with(Vec::new())).is_ok(),
            "control: the empty allowlist the system mode builds must be accepted"
        );
        let err = refuse_the_allowlist_path(&auth_with(vec![[7u8; 32]]))
            .expect_err("a populated allowlist must stop the system mode from starting");
        assert!(
            err.to_string().contains("cannot serve the allowlist path"),
            "the error must say why, got: {err}"
        );
    }

    /// The daemon refuses to start when its own PAM service file is missing
    /// while /etc/pam.d exists. Measured on live systems (spec 6.5): without
    /// the file PAM falls through to /etc/pam.d/other, which ADMITS on
    /// Debian -- an expired account included, where `other` is pam_permit --
    /// and DENIES everyone on Fedora. A packaging slip must not decide who
    /// gets in.
    #[cfg(feature = "system")]
    #[test]
    fn a_missing_pam_service_file_refuses_the_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pam_d = dir.path().join("pam.d");
        std::fs::create_dir(&pam_d).expect("create pam.d");

        let refusal = refuse_without_pam_service(&pam_d, "qshd")
            .expect_err("a missing service file must refuse the start");
        let text = refusal.to_string();
        assert!(
            text.contains("qshd") && text.contains("pam.d"),
            "the refusal must name the file the operator has to create, got {text:?}"
        );

        std::fs::write(pam_d.join("qshd"), "auth required pam_permit.so\n").expect("write");
        assert!(
            refuse_without_pam_service(&pam_d, "qshd").is_ok(),
            "with the file present the start must not be refused"
        );
    }

    /// The other half of the same rule, and the one that keeps it from
    /// breaking machines it has no business breaking: where /etc/pam.d does
    /// not exist at all, the machine uses a single /etc/pam.conf, and a
    /// refusal would be about our assumption rather than about its state.
    #[cfg(feature = "system")]
    #[test]
    fn a_machine_without_a_pam_d_directory_is_not_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let absent = dir.path().join("pam.d");
        assert!(
            refuse_without_pam_service(&absent, "qshd").is_ok(),
            "a machine with no /etc/pam.d uses /etc/pam.conf; refusing it would be our \
             assumption speaking, not its state"
        );
    }

    /// A helper client over a stub that issues nonces at once, and a nonce
    /// pool drawing from it -- the two things the system mode's setup is
    /// built from. The stub is returned so it lives as long as they do.
    #[cfg(feature = "system")]
    fn helper_and_pool() -> (
        Arc<crate::helper::spawner::HelperAuth>,
        Arc<crate::nonce_pool::PooledNonces>,
        crate::nonce_pool::tests::StubHelper,
    ) {
        let (worker_end, stub) = crate::nonce_pool::tests::helper_stub_answering_nonces_at_once();
        let helper = crate::nonce_pool::tests::client(worker_end);
        let pool =
            crate::nonce_pool::PooledNonces::start(Arc::clone(&helper)).expect("the nonce pool");
        (helper, pool, stub)
    }

    /// The system mode refuses, as part of building its own setup, an
    /// allowlist it cannot keep empty: one with a key in it, and one that
    /// somebody else also holds and could add to after the check. The
    /// positive control is exactly what production passes -- a fresh, empty
    /// list -- and it must come out held by the system mode's `ServerAuth`
    /// alone.
    #[cfg(feature = "system")]
    #[test]
    fn building_the_system_mode_refuses_an_allowlist_it_cannot_keep_empty() {
        let (helper, pool, _stub) = helper_and_pool();
        let built = match system_server_auth(
            [0u8; 32],
            helper,
            pool,
            "qshd",
            Arc::new(Mutex::new(Vec::new())),
        ) {
            Ok(built) => built,
            Err(e) => panic!("control: a fresh, empty allowlist must be accepted, got: {e}"),
        };
        assert_eq!(
            Arc::strong_count(&built.allowlist),
            1,
            "control: nothing but the system mode's own ServerAuth may hold its allowlist"
        );

        let (helper, pool, _stub) = helper_and_pool();
        match system_server_auth(
            [0u8; 32],
            helper,
            pool,
            "qshd",
            Arc::new(Mutex::new(vec![[7u8; 32]])),
        ) {
            Ok(_) => panic!("a populated allowlist must stop the system mode from starting"),
            Err(e) => assert!(
                e.to_string().contains("cannot serve the allowlist path"),
                "the error must say why, got: {e}"
            ),
        }

        let (helper, pool, _stub) = helper_and_pool();
        let kept_elsewhere: transport::session_manager::SharedAllowlist =
            Arc::new(Mutex::new(Vec::new()));
        match system_server_auth([0u8; 32], helper, pool, "qshd", Arc::clone(&kept_elsewhere)) {
            Ok(_) => panic!(
                "an allowlist somebody else also holds must stop the system mode from starting, \
                 empty or not: its other holder could add a key after the check"
            ),
            Err(e) => assert!(
                e.to_string().contains("shared"),
                "the error must say why, got: {e}"
            ),
        }
    }

    /// The system mode's nonces and verdicts come from ONE helper-backed
    /// client and nothing else. The verifier and the login sink are the very
    /// `HelperAuth` the setup was handed; the nonce source is the pool it was
    /// handed, and that pool draws from the same `HelperAuth`. A second source
    /// anywhere -- an `AuthorizedKeysVerifier` reading files in the worker, or
    /// locally minted `RandomNonces` -- would decide a login without the
    /// helper.
    #[cfg(feature = "system")]
    #[test]
    fn the_system_mode_asks_the_helper_for_nonces_and_verdicts_alike() {
        let (helper, pool, _stub) = helper_and_pool();
        let auth = system_server_auth(
            [0u8; 32],
            Arc::clone(&helper),
            Arc::clone(&pool),
            "qshd",
            Arc::new(Mutex::new(Vec::new())),
        )
        .expect("the system mode's own setup passes its own startup check");

        let helper_ptr = Arc::as_ptr(&helper).cast::<()>();
        let verifier = auth
            .verifier
            .as_ref()
            .expect("the system mode verifies every signature client");
        assert_eq!(
            Arc::as_ptr(verifier).cast::<()>(),
            helper_ptr,
            "the verifier must be the helper-backed one"
        );
        assert_eq!(
            Arc::as_ptr(&auth.logins).cast::<()>(),
            helper_ptr,
            "the login sink must be the same helper-backed one"
        );
        assert_eq!(
            Arc::as_ptr(&auth.nonces).cast::<()>(),
            Arc::as_ptr(&pool).cast::<()>(),
            "the nonce source must be the pool the setup was handed"
        );
        assert_eq!(
            pool.helper_ptr(),
            helper_ptr,
            "the nonce pool must draw from the same helper-backed client"
        );
    }

    /// The router of the system mode, as `system_server_auth` sets it up, with
    /// a helper that has stopped answering.
    #[cfg(feature = "system")]
    mod silent_helper {
        use super::*;

        use std::future::Future;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        use transport::conn::{AuthPolicy, ConnectionConfig, Role};
        use transport::driver_std::{Binder, ClientEvents, StdClient};
        use transport::handshake::generate_keypair;
        use transport::handshake_payload::StartKind;
        use transport::session_manager::{
            BackendFactory, NonceSource, SessionBackend, SessionInbound, SessionIo, SessionManager,
        };
        use transport::{LinkState, Stats, AUTH_NONCE_LEN};

        use crate::helper::protocol::Response;
        use crate::helper::spawner::HELPER_ANSWER_TIMEOUT;
        use crate::nonce_pool::tests::{client, stub_helper, wait_until, Pace, TEST_WAIT};
        use crate::nonce_pool::PooledNonces;

        /// How long the test watches a handshake the router cannot give a
        /// nonce to: longer than the helper's answer budget, so a router that
        /// waited for the helper is caught doing it.
        const WATCH: Duration = Duration::from_secs(3);

        /// A refusal that took longer than this was not given at once. Far
        /// below the helper's answer budget, far above a lock and a pop on a
        /// loaded machine.
        const REFUSED_AT_ONCE: Duration = Duration::from_millis(250);

        /// A live session going this long without an echo means its datagrams
        /// were not being routed: half the helper's answer budget.
        const STALL: Duration = Duration::from_secs(1);

        /// How long the pool keeps a nonce here: short, so the pool runs dry
        /// on its own once the helper stops answering.
        const MAX_AGE: Duration = Duration::from_millis(300);

        /// How often the live session sends a byte to be echoed.
        const PROBE_EVERY: Duration = Duration::from_millis(20);

        /// Echoes stream 0, and counts the sessions it was given.
        struct Echo {
            granted: Arc<AtomicUsize>,
        }

        impl SessionBackend for Echo {
            fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                self.granted.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    while let Some(event) = io.recv().await {
                        if let SessionInbound::Data(data) = event {
                            if data.stream_id == 0 {
                                io.send(0, data.data);
                            }
                        }
                    }
                })
            }
        }

        /// What one client received on stream 0, and when.
        #[derive(Default)]
        struct Received {
            bytes: Vec<u8>,
            arrivals: Vec<Instant>,
            live: bool,
        }

        #[derive(Default)]
        struct Events(Mutex<Received>);

        impl Events {
            fn received(&self) -> std::sync::MutexGuard<'_, Received> {
                self.0.lock().expect("received")
            }
        }

        impl ClientEvents for Events {
            fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
                if stream_id == 0 {
                    let mut received = self.received();
                    received.bytes.extend(data);
                    received.arrivals.push(Instant::now());
                }
            }
            fn on_state(&self, state: LinkState) {
                if state == LinkState::Live {
                    self.received().live = true;
                }
            }
            fn on_stats(&self, _stats: Stats) {}
            fn on_reset(&self, _stream_id: u8) {}
        }

        struct AnyNetwork;

        impl Binder for AnyNetwork {
            fn bind(&self, _fd: i32) -> bool {
                true
            }
        }

        /// One call the router made for a nonce: when, how long it took, and
        /// whether it got one.
        type Call = (Instant, Duration, bool);

        /// Passes every call on to the source the setup built, and times the
        /// ones the router makes for a nonce.
        struct Timed {
            inner: Arc<dyn NonceSource>,
            calls: Arc<Mutex<Vec<Call>>>,
        }

        impl NonceSource for Timed {
            fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
                let started = Instant::now();
                let issued = self.inner.issue();
                let took = started.elapsed();
                self.calls
                    .lock()
                    .expect("calls")
                    .push((started, took, issued.is_ok()));
                issued
            }
            fn release(&self, nonce: [u8; AUTH_NONCE_LEN]) {
                self.inner.release(nonce);
            }
        }

        fn connect(
            server: std::net::SocketAddr,
            server_pub: [u8; 32],
            token: [u8; 16],
            key: &std::path::Path,
            events: Arc<Events>,
        ) -> StdClient {
            StdClient::connect(
                server,
                ConnectionConfig {
                    features: transport::Features::SUPPORTED,
                    role: Role::Client,
                    local_static_priv: generate_keypair().private,
                    remote_static_pub: Some(server_pub),
                    auth: AuthPolicy::SshSignature,
                },
                token,
                StartKind::Cold,
                Arc::new(AnyNetwork),
                events,
                Some(Arc::new(
                    sshauth::sign_file::FileSigner::load(key, None)
                        .expect("load the key")
                        .with_login("anyone".to_string()),
                )),
            )
        }

        /// With the helper answering nothing at all, the system mode's router
        /// refuses a new handshake at once from its empty pool, and goes on
        /// serving the session it already has: it never waits on the helper
        /// for a nonce.
        ///
        /// A stub helper fills the pool and admits a first client, A, then
        /// stops answering anything, and the pool runs dry as its nonces age
        /// out. A second client, B,
        /// starts a handshake and keeps sending its msg1 again, while A sends
        /// a byte to be echoed every [`PROBE_EVERY`] through the same router.
        /// Every call the router makes for a nonce is timed.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_silent_helper_holds_up_neither_live_sessions_nor_refusals() {
            let dir = tempfile::tempdir().expect("tempdir");
            let key_path = dir.path().join("key");
            let key =
                ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                    .expect("keygen");
            std::fs::write(
                &key_path,
                key.to_openssh(ssh_key::LineEnding::LF)
                    .expect("encode")
                    .as_bytes(),
            )
            .expect("write the key");

            let silent = Arc::new(AtomicBool::new(false));
            let pace_silent = Arc::clone(&silent);
            let (worker, stub) = stub_helper(
                move |_| {
                    if pace_silent.load(Ordering::SeqCst) {
                        Pace::Never
                    } else {
                        Pace::After(Duration::ZERO)
                    }
                },
                Some(Response::Verified {
                    uid: 4242,
                    name: "anyone".to_string(),
                    identity: "SHA256:anyone".to_string(),
                    incarnation: 0,
                }),
            );
            let helper = client(worker);
            let pool =
                PooledNonces::with_max_age(Arc::clone(&helper), MAX_AGE).expect("the nonce pool");
            let server_kp = generate_keypair();
            let mut auth = system_server_auth(
                server_kp.public,
                helper,
                Arc::clone(&pool),
                "qshd",
                Arc::new(Mutex::new(Vec::new())),
            )
            .expect("the system mode's setup");
            let calls = Arc::new(Mutex::new(Vec::<Call>::new()));
            auth.nonces = Arc::new(Timed {
                inner: auth.nonces,
                calls: Arc::clone(&calls),
            });

            let socket = Arc::new(
                tokio::net::UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("bind"),
            );
            let addr = socket.local_addr().expect("addr");
            let granted = Arc::new(AtomicUsize::new(0));
            let server = tokio::spawn(SessionManager::serve(
                socket,
                server_kp.private,
                auth,
                BackendFactory(Arc::new(Echo {
                    granted: Arc::clone(&granted),
                })),
                Arc::new(AtomicUsize::new(0)),
                LoginEndedReports::none(),
            ));

            // A gets in while the helper still answers.
            let a_events = Arc::new(Events::default());
            let a = Arc::new(connect(
                addr,
                server_kp.public,
                [1u8; 16],
                &key_path,
                Arc::clone(&a_events),
            ));
            a.send_bytes(0, b"hello".to_vec());
            assert!(
                wait_until(TEST_WAIT, || a_events.received().bytes == b"hello"),
                "setup: the first client must get its session"
            );

            // The helper goes silent, and the pool runs dry by ageing:
            // nothing here takes a nonce out of it, so the router's own call
            // is the first to find it empty. Once the stub has left a request
            // unanswered, the pool's thread is waiting on it -- it asks one
            // at a time -- and every nonce answered before has reached the
            // pool, to age out within `MAX_AGE`.
            silent.store(true, Ordering::SeqCst);
            assert!(
                wait_until(TEST_WAIT, || stub.ignored() > 0),
                "setup: the pool's thread must be left waiting on the silent helper"
            );
            assert!(
                wait_until(TEST_WAIT, || pool.snapshot().is_empty()),
                "setup: the pool must run dry once the helper is silent"
            );

            let probing = Arc::new(AtomicBool::new(true));
            let probe = std::thread::spawn({
                let a = Arc::clone(&a);
                let probing = Arc::clone(&probing);
                move || {
                    while probing.load(Ordering::SeqCst) {
                        a.send_bytes(0, b".".to_vec());
                        std::thread::sleep(PROBE_EVERY);
                    }
                }
            });
            // Let the probe's echoes start before B does.
            assert!(
                wait_until(TEST_WAIT, || a_events.received().bytes.len()
                    > b"hello".len()),
                "setup: the probe's bytes must come back"
            );

            let b_events = Arc::new(Events::default());
            let watch_from = Instant::now();
            let b = connect(
                addr,
                server_kp.public,
                [2u8; 16],
                &key_path,
                Arc::clone(&b_events),
            );
            b.send_bytes(0, b"hello".to_vec());
            std::thread::sleep(WATCH);
            let watch_until = Instant::now();
            probing.store(false, Ordering::SeqCst);
            probe.join().expect("the probe");

            let asked: Vec<Call> = calls
                .lock()
                .expect("calls")
                .iter()
                .copied()
                .filter(|(at, _, _)| *at >= watch_from)
                .collect();
            let echoes: Vec<Instant> = a_events
                .received()
                .arrivals
                .iter()
                .copied()
                .filter(|at| *at >= watch_from && *at <= watch_until)
                .collect();
            let b_got_in = b_events.received().live || !b_events.received().bytes.is_empty();
            b.close();
            a.close();
            server.abort();

            assert!(
                !asked.is_empty(),
                "setup: the second client's handshake must reach the router and ask for a nonce"
            );
            assert!(
                asked.iter().all(|(_, _, got)| !got) && !b_got_in,
                "the second client must be refused: the pool is empty and the helper silent \
                 ({asked:?}, got in: {b_got_in})"
            );
            let slowest = asked
                .iter()
                .map(|(_, took, _)| *took)
                .max()
                .unwrap_or_default();
            assert!(
                slowest < REFUSED_AT_ONCE,
                "the router waited {slowest:?} for a nonce with the pool empty; it must be \
                 refused at once, not after a round trip to the helper ({:?} budget)",
                HELPER_ANSWER_TIMEOUT
            );
            let mut edges = vec![watch_from];
            edges.extend(echoes);
            edges.push(watch_until);
            let longest_silence = edges
                .windows(2)
                .map(|pair| pair[1] - pair[0])
                .max()
                .unwrap_or_default();
            println!(
                "silent helper: {} nonce calls, slowest {slowest:?}; {} echoes, longest silence \
                 {longest_silence:?}",
                asked.len(),
                edges.len() - 2
            );
            assert!(
                longest_silence < STALL,
                "the live session went {longest_silence:?} without an echo while a new \
                 handshake was being refused: the router stopped routing it"
            );
            assert_eq!(
                granted.load(Ordering::SeqCst),
                1,
                "only the first client may ever have been given a session"
            );
            assert_eq!(
                stub.verifies(),
                1,
                "only the first client may ever have reached the helper with a proof"
            );
        }
        /// A helper that is alive but has stopped reading, its seam full. The
        /// router still ends logins (a graceful close) and releases nonces (a
        /// probation that ends unproven) on its own task; neither may wait on
        /// the full socket. A live session's echo is timed meanwhile.
        ///
        /// From the review of the nonce pool, where it measured the router held
        /// for 2 s by each `login_ended` and for 4 s by each `release`.
        mod stuck_helper {
            use super::*;

            use std::os::unix::net::UnixStream;

            use transport::auth::{AuthError, AuthRecord, AuthVerifier};
            use transport::session_manager::{LoginId, LoginSink};

            use crate::helper::channel;
            use crate::helper::protocol::{decode, encode, AuthRequest, AuthResponse, Request};

            /// How long each phase is watched: past a send timeout, and in
            /// the second phase past a probation's whole course as well.
            const PHASE_L: Duration = Duration::from_secs(5);
            const PHASE_R: Duration = Duration::from_secs(9);

            /// How many clients try to log in in the second phase: as many as
            /// may be verified at once (`transport`'s
            /// `MAX_CONCURRENT_VERIFIES`), so every permit is in play.
            const LATECOMERS: u8 = 4;

            struct StuckStub {
                reading: Arc<AtomicBool>,
                stopped: Arc<AtomicBool>,
                quit: Arc<AtomicBool>,
            }

            /// A stub helper that answers until `reading` is cleared, then
            /// holds its end open and never reads again. The first `admit`
            /// verifications are admitted, every later one refused.
            fn stuck_stub(admit: usize) -> (UnixStream, StuckStub) {
                let (worker, stub_end) = channel::pair().expect("socketpair");
                let stub = StuckStub {
                    reading: Arc::new(AtomicBool::new(true)),
                    stopped: Arc::new(AtomicBool::new(false)),
                    quit: Arc::new(AtomicBool::new(false)),
                };
                let reading = Arc::clone(&stub.reading);
                let stopped = Arc::clone(&stub.stopped);
                let quit = Arc::clone(&stub.quit);
                std::thread::spawn(move || {
                    let mut issued: u64 = 0;
                    let mut verified = 0usize;
                    while reading.load(Ordering::SeqCst) {
                        let Ok(Some((bytes, _fd))) = channel::recv(&stub_end) else {
                            return;
                        };
                        let AuthRequest { id, body } =
                            decode::<AuthRequest>(&bytes).expect("decode");
                        let answer = match body {
                            Request::Nonce => {
                                issued += 1;
                                let mut nonce = [0x33u8; AUTH_NONCE_LEN];
                                nonce[..8].copy_from_slice(&issued.to_be_bytes());
                                Some(Response::Nonce { nonce })
                            }
                            Request::Verify { .. } => {
                                verified += 1;
                                Some(if verified <= admit {
                                    Response::Verified {
                                        uid: 4242,
                                        name: "anyone".to_string(),
                                        identity: "SHA256:anyone".to_string(),
                                        incarnation: 0,
                                    }
                                } else {
                                    Response::Refused {
                                        reason: "authentication failed".to_string(),
                                    }
                                })
                            }
                            _ => None,
                        };
                        if let Some(body) = answer {
                            let _ = channel::send(
                                &stub_end,
                                &encode(&AuthResponse { id, body }).expect("encode"),
                                None,
                            );
                        }
                    }
                    stopped.store(true, Ordering::SeqCst);
                    // Alive, its end open, reading nothing.
                    while !quit.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    drop(stub_end);
                });
                (worker, stub)
            }

            /// One call the router made: which, when it began, and how long
            /// it took -- `None` while it has not returned. Recorded as it
            /// begins, so a call that never comes back is seen too.
            type RouterCall = (&'static str, Instant, Option<Duration>);

            type RouterCalls = Arc<Mutex<Vec<RouterCall>>>;

            /// Runs `call`, recording it in `calls` as it begins and its
            /// length once it returns.
            fn timed<T>(calls: &RouterCalls, what: &'static str, call: impl FnOnce() -> T) -> T {
                let started = Instant::now();
                let index = {
                    let mut calls = calls.lock().expect("calls");
                    calls.push((what, started, None));
                    calls.len() - 1
                };
                let result = call();
                calls.lock().expect("calls")[index].2 = Some(started.elapsed());
                result
            }

            struct TimedSource {
                inner: Arc<dyn NonceSource>,
                calls: RouterCalls,
            }

            impl NonceSource for TimedSource {
                fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
                    timed(&self.calls, "issue", || self.inner.issue())
                }
                fn release(&self, nonce: [u8; AUTH_NONCE_LEN]) {
                    timed(&self.calls, "release", || self.inner.release(nonce));
                }
            }

            struct TimedLogins {
                inner: Arc<dyn LoginSink>,
                calls: RouterCalls,
            }

            /// Times verifications too -- not a call on the router's task,
            /// but a request to the helper whose wait holds a probation's
            /// verification permit.
            struct TimedVerifier {
                inner: Arc<dyn AuthVerifier>,
                calls: RouterCalls,
            }

            impl AuthVerifier for TimedVerifier {
                fn verify(
                    &self,
                    handshake_hash: &[u8; 32],
                    record: &AuthRecord,
                    login: LoginId,
                    rhost: &str,
                ) -> Result<Principal, AuthError> {
                    timed(&self.calls, "verify", || {
                        self.inner.verify(handshake_hash, record, login, rhost)
                    })
                }
            }

            impl LoginSink for TimedLogins {
                fn login_ended(&self, login: LoginId) {
                    timed(&self.calls, "login_ended", || self.inner.login_ended(login));
                }
            }

            fn longest_silence(arrivals: &[Instant], from: Instant, until: Instant) -> Duration {
                let mut edges = vec![from];
                edges.extend(
                    arrivals
                        .iter()
                        .copied()
                        .filter(|at| *at >= from && *at <= until),
                );
                edges.push(until);
                edges
                    .windows(2)
                    .map(|pair| pair[1] - pair[0])
                    .max()
                    .unwrap_or_default()
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn a_stuck_helper_with_a_full_seam_does_not_hold_up_the_router() {
                let dir = tempfile::tempdir().expect("tempdir");
                let key_path = dir.path().join("key");
                let key =
                    ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                        .expect("keygen");
                std::fs::write(
                    &key_path,
                    key.to_openssh(ssh_key::LineEnding::LF)
                        .expect("encode")
                        .as_bytes(),
                )
                .expect("write the key");

                // A and C are admitted; any later proof is refused, if it ever
                // reaches the stub.
                let (worker, stub) = stuck_stub(2);
                let helper = client(worker);
                // A long age: the pool keeps what it holds throughout.
                let pool =
                    PooledNonces::with_max_age(Arc::clone(&helper), Duration::from_secs(600))
                        .expect("the nonce pool");
                let server_kp = generate_keypair();
                let mut auth = system_server_auth(
                    server_kp.public,
                    Arc::clone(&helper),
                    Arc::clone(&pool),
                    "qshd",
                    Arc::new(Mutex::new(Vec::new())),
                )
                .expect("the system mode's setup");
                let calls = Arc::new(Mutex::new(Vec::<RouterCall>::new()));
                auth.nonces = Arc::new(TimedSource {
                    inner: auth.nonces,
                    calls: Arc::clone(&calls),
                });
                auth.logins = Arc::new(TimedLogins {
                    inner: auth.logins,
                    calls: Arc::clone(&calls),
                });
                auth.verifier = Some(Arc::new(TimedVerifier {
                    inner: auth.verifier.expect("the system mode verifies"),
                    calls: Arc::clone(&calls),
                }));

                let socket = Arc::new(
                    tokio::net::UdpSocket::bind("127.0.0.1:0")
                        .await
                        .expect("bind"),
                );
                let addr = socket.local_addr().expect("addr");
                let granted = Arc::new(AtomicUsize::new(0));
                let server = tokio::spawn(SessionManager::serve(
                    socket,
                    server_kp.private,
                    auth,
                    BackendFactory(Arc::new(Echo {
                        granted: Arc::clone(&granted),
                    })),
                    Arc::new(AtomicUsize::new(0)),
                    LoginEndedReports::none(),
                ));

                let a_events = Arc::new(Events::default());
                let a = Arc::new(connect(
                    addr,
                    server_kp.public,
                    [1u8; 16],
                    &key_path,
                    Arc::clone(&a_events),
                ));
                a.send_bytes(0, b"hello".to_vec());
                assert!(
                    wait_until(TEST_WAIT, || a_events.received().bytes == b"hello"),
                    "setup: A must get its session"
                );
                let c_events = Arc::new(Events::default());
                let c = connect(
                    addr,
                    server_kp.public,
                    [3u8; 16],
                    &key_path,
                    Arc::clone(&c_events),
                );
                c.send_bytes(0, b"hello".to_vec());
                assert!(
                    wait_until(TEST_WAIT, || c_events.received().bytes == b"hello"),
                    "setup: C must get its session"
                );
                assert!(
                    wait_until(TEST_WAIT, || pool.snapshot().len()
                        == crate::nonce_pool::POOL_TARGET),
                    "setup: the pool must be full again"
                );

                stub.reading.store(false, Ordering::SeqCst);
                // The stub may be blocked reading: hand it one last message.
                helper.release([0xEEu8; AUTH_NONCE_LEN]);
                assert!(
                    wait_until(TEST_WAIT, || stub.stopped.load(Ordering::SeqCst)),
                    "setup: the stub must stop reading"
                );
                // Fill the worker-to-helper direction until the kernel
                // refuses more, the way the test that pins the send timeout
                // does.
                let raw = helper.raw_fd_for_test();
                let filler = [0u8; 100];
                let mut filled = 0usize;
                loop {
                    match nix::sys::socket::send(
                        raw,
                        &filler,
                        nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                    ) {
                        Ok(_) => filled += 1,
                        Err(nix::Error::EAGAIN) => break,
                        Err(e) => panic!("filling failed after {filled}: {e}"),
                    }
                    assert!(filled < 1_000_000, "setup: the seam never filled");
                }

                let probing = Arc::new(AtomicBool::new(true));
                let probe = std::thread::spawn({
                    let a = Arc::clone(&a);
                    let probing = Arc::clone(&probing);
                    move || {
                        while probing.load(Ordering::SeqCst) {
                            a.send_bytes(0, b".".to_vec());
                            std::thread::sleep(PROBE_EVERY);
                        }
                    }
                });
                let echoed = a_events.received().bytes.len();
                assert!(
                    wait_until(TEST_WAIT, || a_events.received().bytes.len() > echoed + 3),
                    "setup: the probe's bytes must come back"
                );

                // Phase L: C closes gracefully; the router ends its login.
                let l_from = Instant::now();
                std::thread::spawn(move || c.close());
                std::thread::sleep(PHASE_L);
                let l_until = Instant::now();

                // Phase R: latecomers are handed nonces from the pool; their
                // proofs cannot reach the helper, and the router releases the
                // nonces.
                let r_from = Instant::now();
                let latecomers: Vec<StdClient> = (0..LATECOMERS)
                    .map(|n| {
                        let client = connect(
                            addr,
                            server_kp.public,
                            [0x20 + n; 16],
                            &key_path,
                            Arc::new(Events::default()),
                        );
                        client.send_bytes(0, b"hello".to_vec());
                        client
                    })
                    .collect();
                std::thread::sleep(PHASE_R);
                let r_until = Instant::now();
                probing.store(false, Ordering::SeqCst);
                probe.join().expect("the probe");

                let arrivals = a_events.received().arrivals.clone();
                let silence_l = longest_silence(&arrivals, l_from, l_until);
                let silence_r = longest_silence(&arrivals, r_from, r_until);
                let looked_at = Instant::now();
                let calls: Vec<RouterCall> = calls.lock().expect("calls").clone();
                // A call still running when the calls are looked at has taken
                // at least that long.
                let in_phase = |from: Instant, until: Instant| -> Vec<(&'static str, Duration)> {
                    calls
                        .iter()
                        .filter(|(_, at, _)| *at >= from && *at <= until)
                        .map(|(what, at, took)| (*what, took.unwrap_or_else(|| looked_at - *at)))
                        .collect()
                };
                let calls_l = in_phase(l_from, l_until);
                let calls_r = in_phase(r_from, r_until);
                println!(
                    "stuck helper: filled {filled} | phase L: longest silence {silence_l:?}, \
                     router calls {calls_l:?} | phase R: longest silence {silence_r:?}, router \
                     calls {calls_r:?} | granted {}",
                    granted.load(Ordering::SeqCst)
                );
                stub.quit.store(true, Ordering::SeqCst);
                server.abort();
                std::thread::spawn(move || {
                    for client in latecomers {
                        client.close();
                    }
                    a.close();
                });

                // What the test is about first; whether the setup produced the
                // two calls after.
                let slowest = calls_l
                    .iter()
                    .chain(calls_r.iter())
                    .filter(|(what, _)| matches!(*what, "release" | "login_ended"))
                    .map(|(_, took)| *took)
                    .max()
                    .unwrap_or_default();
                let verifications: Vec<Duration> = calls_r
                    .iter()
                    .filter(|(what, _)| *what == "verify")
                    .map(|(_, took)| *took)
                    .collect();
                let slowest_verification = verifications.iter().max().copied().unwrap_or_default();
                assert!(
                    slowest < REFUSED_AT_ONCE,
                    "a tell to the helper held the router's task for {slowest:?}"
                );
                assert!(
                    silence_l < STALL && silence_r < STALL,
                    "the live session went {silence_l:?} (login ended) / {silence_r:?} (nonce \
                     released) without an echo: the router stopped routing it"
                );
                assert!(
                    slowest_verification < REFUSED_AT_ONCE,
                    "with a login's end stuck, a verification must fail at once rather than wait \
                     for the send lock, holding its permit: the slowest of {} took \
                     {slowest_verification:?}",
                    verifications.len()
                );
                assert!(
                    !verifications.is_empty(),
                    "setup: the latecomers' proofs must reach the verifier: {calls_r:?}"
                );
                assert!(
                    calls_l.iter().any(|(what, _)| *what == "login_ended"),
                    "setup: C's graceful close must reach the router's login sink: {calls_l:?}"
                );
                assert!(
                    calls_r.iter().any(|(what, _)| *what == "release"),
                    "setup: an unproven probation must make the router release its nonce: \
                     {calls_r:?}"
                );
            }
        }
    }
}
