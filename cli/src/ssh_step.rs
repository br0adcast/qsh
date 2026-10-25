//! Step 2 of the ladder: log in over ssh and bring `qshd` up.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::install_ui::InstallProgress;
use crate::known_hosts::{entry_name, HostKeys, KnownHosts};
use crate::prompt::{SshPrompter, Tty};

/// Bounds the TCP connect, the greeting and each network wait of the login.
pub const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How many times the password is asked, as OpenSSH does.
pub const PASSWORD_PROMPTS: usize = 3;
const KEEPALIVE: Duration = Duration::from_secs(15);

/// `id_ed25519`, `id_ecdsa`, `id_rsa` of `ssh_dir`, those that exist.
pub fn default_key_files(ssh_dir: &Path) -> Vec<PathBuf> {
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|n| ssh_dir.join(n))
        .filter(|p| p.is_file())
        .collect()
}

/// The login methods in OpenSSH order: `-i`, the agent, default key files,
/// then (unless `no_password`) keyboard-interactive and the password.
pub fn plan_methods(
    identity: Option<&Path>,
    agent: Option<&Path>,
    key_files: &[PathBuf],
    no_password: bool,
) -> Vec<ssh::AuthMethod> {
    let mut methods = Vec::new();
    if let Some(i) = identity {
        methods.push(ssh::AuthMethod::KeyFile(i.to_path_buf()));
    }
    if let Some(a) = agent {
        methods.push(ssh::AuthMethod::Agent(a.to_path_buf()));
    }
    for f in key_files {
        if identity != Some(f.as_path()) {
            methods.push(ssh::AuthMethod::KeyFile(f.clone()));
        }
    }
    if !no_password {
        methods.push(ssh::AuthMethod::KeyboardInteractive);
        for _ in 0..PASSWORD_PROMPTS {
            methods.push(ssh::AuthMethod::AskPassword);
        }
    }
    methods
}

/// What a `bring_up` error says about the ssh host key.
pub enum HostKeyVerdict {
    Ask(ssh::HostKeyInfo),
    Refuse(String),
    NotAboutTheKey,
}

pub fn judge_host_key(
    err: &ssh::SshError,
    keys: &HostKeys,
    name: &str,
    store: &KnownHosts,
) -> HostKeyVerdict {
    let (info, changed) = match err {
        ssh::SshError::UnknownHostKey(i) => (i, false),
        ssh::SshError::HostKeyChanged(i) => (i, true),
        _ => return HostKeyVerdict::NotAboutTheKey,
    };
    if keys.revoked.contains(&info.key) {
        return HostKeyVerdict::Refuse(format!(
            "the ssh host key of {name} ({}) is marked @revoked in the configured known-hosts files: {}",
            info.fingerprint, store_paths(store)
        ));
    }
    if changed {
        return HostKeyVerdict::Refuse(changed_text(name, info, store));
    }
    HostKeyVerdict::Ask(info.clone())
}

fn changed_text(name: &str, info: &ssh::HostKeyInfo, store: &KnownHosts) -> String {
    format!(
        "WARNING: the ssh host key of {name} has changed (now {}); not using ssh there. \
         If this is expected, find and remove the old key in the configured known-hosts files: {}",
        info.fingerprint,
        store_paths(store)
    )
}

fn store_paths(store: &KnownHosts) -> String {
    store
        .files()
        .map(|path| format!("\"{}\"", path.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn unknown_key_question(name: &str, info: &ssh::HostKeyInfo) -> String {
    let kind = info
        .key_type
        .strip_prefix("ssh-")
        .unwrap_or(&info.key_type)
        .to_ascii_uppercase();
    format!(
        "The authenticity of host '{name}' can't be established.\n\
         {kind} key fingerprint is {}.\n\
         Are you sure you want to continue connecting",
        info.fingerprint
    )
}

/// What to do about an ssh host key nobody has seen before.
#[derive(Debug, PartialEq, Eq)]
pub enum UnknownHostKey {
    /// Ask the person this question.
    Ask(String),
    /// Nobody to ask: a background round skips ssh at this address.
    Skip,
}

/// Whether an unknown ssh host key is a question, and which: never in the
/// background, where the terminal belongs to the live session.
pub fn unknown_host_key(background: bool, name: &str, info: &ssh::HostKeyInfo) -> UnknownHostKey {
    if background {
        UnknownHostKey::Skip
    } else {
        UnknownHostKey::Ask(unknown_key_question(name, info))
    }
}

/// The ssh login's questions in the background: nobody answers them, and a
/// login that failed after asking one failed for want of a person, not for
/// any fault of the address.
#[derive(Default)]
pub struct Unanswered {
    asked: AtomicBool,
}

impl Unanswered {
    /// Whether the login asked anything so far.
    pub fn asked(&self) -> bool {
        self.asked.load(Ordering::SeqCst)
    }

    fn note(&self) {
        self.asked.store(true, Ordering::SeqCst);
    }
}

impl ssh::AuthPrompter for Unanswered {
    fn passphrase(&self, _: &Path) -> Option<ssh::Zeroizing<String>> {
        self.note();
        None
    }

    fn password(&self, _: &str, _: &str) -> Option<ssh::Zeroizing<String>> {
        self.note();
        None
    }

    fn keyboard_interactive(
        &self,
        _: &str,
        _: &str,
        _: &[ssh::Prompt],
    ) -> Option<Vec<ssh::Zeroizing<String>>> {
        self.note();
        None
    }
}

/// Why step 2 did not bring qshd up.
#[derive(Debug, PartialEq, Eq)]
pub enum SshStepError {
    /// The installation was offered and declined for this login.
    InstallDeclined,
    /// Background only: the step needed a question nobody may ask now.
    NeedsPrompt,
    /// What to say after "ssh: ", and whether it looks like a denied
    /// Local Network permission.
    Failed(::connect::SshFailure),
}

/// A failure that is only words.
fn plain(why: impl Into<String>) -> SshStepError {
    SshStepError::Failed(::connect::SshFailure::plain(why))
}

/// An ssh error as the step's failure: its words, and whether it is macOS's
/// "no route" to a local address -- how a denied Local Network permission
/// looks (`sshauth::addr::local_network_hint`).
fn ssh_failure(e: &ssh::SshError, on_macos: bool) -> ::connect::SshFailure {
    let local_network_hint = match e {
        ssh::SshError::Unreachable { target, kind, .. } => {
            sshauth::addr::local_network_hint(on_macos, *kind, target.ip())
        }
        _ => false,
    };
    ::connect::SshFailure {
        why: e.to_string(),
        local_network_hint,
        cause: if matches!(e, ssh::SshError::CryptoBusy) {
            ::connect::SshFailureCause::CryptoBusy
        } else {
            ::connect::SshFailureCause::Other
        },
    }
}

pub struct SshStep<'a> {
    pub login: &'a str,
    pub identity: Option<&'a Path>,
    pub no_password: bool,
    /// `$SSH_AUTH_SOCK`, read once by `main`: the core never reads it.
    pub agent: Option<PathBuf>,
    /// `~/.ssh`, for id_ed25519, id_ecdsa, id_rsa.
    pub ssh_dir: Option<PathBuf>,
    pub known_hosts: &'a KnownHosts,
    pub tty: &'a Tty,
    /// A reconnect round behind the live terminal: nothing is asked, and
    /// `tty` is never touched.
    pub background: bool,
    pub images: Arc<dyn bringup::ImageSource>,
}

/// Who answers the login's questions, and -- in the background -- the one
/// that remembers whether anything was asked.
struct Prompter {
    answers: Arc<dyn ssh::AuthPrompter>,
    unanswered: Option<Arc<Unanswered>>,
}

impl Prompter {
    /// Whether this login failed for want of an answer.
    fn went_unanswered(&self) -> bool {
        self.unanswered.as_ref().is_some_and(|u| u.asked())
    }
}

impl SshStep<'_> {
    fn prompter(&self) -> Prompter {
        if self.no_password {
            // `--no-password` asks nothing anywhere: a login that needed an
            // answer is an ordinary failure, not a question put off.
            Prompter {
                answers: Arc::new(ssh::NoPrompts),
                unanswered: None,
            }
        } else if self.background {
            let u = Arc::new(Unanswered::default());
            Prompter {
                answers: u.clone(),
                unanswered: Some(u),
            }
        } else {
            Prompter {
                answers: Arc::new(SshPrompter(self.tty.clone())),
                unanswered: None,
            }
        }
    }

    fn request(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        keys: &HostKeys,
        prompter: Arc<dyn ssh::AuthPrompter>,
    ) -> bringup::BringUpRequest {
        let key_files = self
            .ssh_dir
            .as_deref()
            .map(default_key_files)
            .unwrap_or_default();
        bringup::BringUpRequest {
            name: "console".into(),
            ssh: ssh::SshParams {
                host: addr.host.clone(),
                port: route.port,
                username: self.login.to_string(),
                known_host_keys: keys.known.clone(),
                connect_timeout: SSH_CONNECT_TIMEOUT,
                keepalive_interval: KEEPALIVE,
                compression: false,
                tcp_nodelay: true,
                knock: route.knock.clone(),
            },
            auth: ssh::SshAuthPlan {
                methods: plan_methods(
                    self.identity,
                    self.agent.as_deref(),
                    &key_files,
                    self.no_password,
                ),
                prompter,
            },
            qsh_port: addr.qsh_port,
            client_pubkey,
        }
    }

    /// One login and bringup. A login refused after an unanswered question
    /// is `Unanswered`: the same address may well work once a person is there.
    fn attempt(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        keys: &HostKeys,
        cancel: &knock::Cancel,
    ) -> Result<bringup::IdentifiedReady, Attempted> {
        let prompter = self.prompter();
        let result = bringup::bring_up_identified(
            self.request(addr, route, client_pubkey, keys, prompter.answers.clone()),
            if self.background {
                bringup::InstallPolicy::ExistingOnly
            } else {
                bringup::InstallPolicy::AskIfMissing {
                    version: env!("CARGO_PKG_VERSION").into(),
                }
            },
            bringup::BringUpHooks {
                source: Some(self.images.clone()),
                approval: Arc::new(InstallQuestion(self.tty.clone())),
                observer: Arc::new(InstallProgress::new(self.background)),
                timing: bringup::InstallTiming::default(),
            },
            Arc::new(knock::NoBind),
            cancel,
        );
        match result {
            Ok(ready) => Ok(ready),
            // Only the login itself: a login that got in after an unanswered
            // passphrase (the agent had the key) and then failed later failed
            // for its own reason.
            Err(bringup::BringUpError::Ssh(ssh::SshError::AuthFailed(_)))
                if prompter.went_unanswered() =>
            {
                Err(Attempted::Unanswered)
            }
            Err(bringup::BringUpError::Ssh(e)) => Err(Attempted::Ssh(e)),
            Err(bringup::BringUpError::Declined) => Err(Attempted::InstallDeclined),
            Err(bringup::BringUpError::InstallRequired) => Err(Attempted::Unanswered),
            Err(other) => Err(Attempted::Other(other.to_string())),
        }
    }

    /// Step 2 for one address: knock, log in, bring qshd up with
    /// `client_pubkey`.
    pub fn run(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        cancel: &knock::Cancel,
    ) -> Result<bringup::Ready, SshStepError> {
        self.run_identified(addr, route, client_pubkey, cancel)
            .map(|identified| identified.ready)
    }

    /// Foreground bootstrap, retaining the key checked by its actual login.
    /// A background caller must supply explicit bindings through `run_bound`.
    pub fn run_identified(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        cancel: &knock::Cancel,
    ) -> Result<bringup::IdentifiedReady, SshStepError> {
        if self.background {
            return Err(SshStepError::NeedsPrompt);
        }
        crate::signals::with_termination_cancel(cancel, || {
            self.run_inner(addr, route, client_pubkey, cancel)
        })
    }

    /// Background bringup permits only the intersection of explicit binding
    /// keys and freshly read OpenSSH trust, with revocations taking precedence.
    /// The restricted keys reach the real login's KEX before user authentication.
    pub fn run_bound(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        bound_keys: &[Vec<u8>],
        cancel: &knock::Cancel,
    ) -> Result<bringup::Ready, SshStepError> {
        self.run_bound_observed(addr, route, client_pubkey, bound_keys, cancel, || {})
    }

    /// Observation starts only after the existing trust restrictions admit an
    /// attempt. The callback cannot grant trust or affect the result.
    pub(crate) fn run_bound_observed(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        bound_keys: &[Vec<u8>],
        cancel: &knock::Cancel,
        started: impl FnOnce(),
    ) -> Result<bringup::Ready, SshStepError> {
        if !self.background || cancel.is_cancelled() {
            return Err(SshStepError::NeedsPrompt);
        }
        let mut keys = self
            .known_hosts
            .lookup(&addr.host, route.port)
            .map_err(|error| plain(error.to_string()))?;
        keys.known
            .retain(|key| bound_keys.contains(key) && !keys.revoked.contains(key));
        if keys.known.is_empty() {
            return Err(SshStepError::NeedsPrompt);
        }
        started();
        self.attempt(addr, route, client_pubkey, &keys, cancel)
            .map(|identified| identified.ready)
            .map_err(Attempted::into_error)
    }

    fn run_inner(
        &self,
        addr: &::connect::Address,
        route: &::connect::SshRoute,
        client_pubkey: [u8; 32],
        cancel: &knock::Cancel,
    ) -> Result<bringup::IdentifiedReady, SshStepError> {
        let name = entry_name(&addr.host, route.port);
        let mut keys = self
            .known_hosts
            .lookup(&addr.host, route.port)
            .map_err(|error| plain(error.to_string()))?;
        let first = match self.attempt(addr, route, client_pubkey, &keys, cancel) {
            Ok(ready) => return Ok(ready),
            Err(Attempted::Ssh(e)) => e,
            Err(other) => return Err(other.into_error()),
        };
        let info = match judge_host_key(&first, &keys, &name, self.known_hosts) {
            HostKeyVerdict::Refuse(why) => return Err(plain(why)),
            HostKeyVerdict::NotAboutTheKey => {
                return Err(SshStepError::Failed(ssh_failure(
                    &first,
                    cfg!(target_os = "macos"),
                )))
            }
            HostKeyVerdict::Ask(info) => info,
        };
        let question = match unknown_host_key(self.background, &name, &info) {
            UnknownHostKey::Skip => return Err(SshStepError::NeedsPrompt),
            UnknownHostKey::Ask(q) => q,
        };
        if !self.tty.confirm(&question) {
            return Err(plain("the ssh host key was not accepted"));
        }
        if let Err(err) = self
            .known_hosts
            .add(&addr.host, route.port, &info.key_type, &info.key)
        {
            eprintln!(
                "qsh: could not save the key to {}: {err}",
                self.known_hosts.user_file().display()
            );
        }
        keys.known.push(info.key);
        // The second connection (and knock) is how `ssh::connect` works.
        match self.attempt(addr, route, client_pubkey, &keys, cancel) {
            Ok(ready) => Ok(ready),
            Err(Attempted::Ssh(e)) => {
                Err(match judge_host_key(&e, &keys, &name, self.known_hosts) {
                    HostKeyVerdict::Refuse(why) => plain(why),
                    HostKeyVerdict::Ask(info) => {
                        plain(changed_text(&name, &info, self.known_hosts))
                    }
                    HostKeyVerdict::NotAboutTheKey => {
                        SshStepError::Failed(ssh_failure(&e, cfg!(target_os = "macos")))
                    }
                })
            }
            Err(other) => Err(other.into_error()),
        }
    }
}

struct InstallQuestion(Tty);
impl bringup::InstallApproval for InstallQuestion {
    fn approve(
        &self,
        offer: &bringup::InstallOffer,
        cancel: &knock::Cancel,
    ) -> Result<bool, bringup::BringUpError> {
        let question = format!(
            "\nqshd is not installed on {}@{}:{}.\n\n  Version   {}\n  Platform  {}\n  Location  {}\n  Source    GitHub Releases\n\nInstall qshd {}?",
            crate::report::printable(&offer.username),
            crate::report::printable(&offer.host),
            offer.ssh_port,
            offer.image.version,
            offer.image.platform.target(),
            crate::report::printable(&offer.remote_path),
            offer.image.version,
        );
        self.0
            .confirm_install(&question, cancel)
            .map_err(bringup::BringUpError::Ssh)
    }
}

/// How one `bring_up` did not work.
enum Attempted {
    /// The ssh login itself; the host key may be what it is about.
    Ssh(ssh::SshError),
    /// A later stage of the bringup, as the line to print.
    Other(String),
    InstallDeclined,
    /// It asked a question in the background, and nobody answered.
    Unanswered,
}

impl Attempted {
    /// Anything but an ssh error that still has to be judged.
    fn into_error(self) -> SshStepError {
        match self {
            Attempted::Ssh(e) => SshStepError::Failed(ssh_failure(&e, cfg!(target_os = "macos"))),
            Attempted::Other(why) => plain(why),
            Attempted::Unanswered => SshStepError::NeedsPrompt,
            Attempted::InstallDeclined => SshStepError::InstallDeclined,
        }
    }
}

// The real-daemon sandbox uses Linux pidfds for owned cleanup. Portable
// bootstrap fixtures include their fake SSH server directly instead.
#[cfg(all(test, target_os = "linux"))]
#[path = "../../crates/bringup/tests/support_home/mod.rs"]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(target_os = "linux")]
    use super::test_support as support_home;

    #[test]
    fn installation_approval_propagates_confirmation_cancellation() {
        use bringup::InstallApproval;
        let cancel = knock::Cancel::new();
        cancel.cancel();
        let offer = bringup::InstallOffer {
            username: "fixture".into(),
            host: "host.invalid".into(),
            ssh_port: 22,
            image: bringup::ImageRequest::new(
                bringup::Platform::from_uname("Linux", "x86_64").unwrap(),
                "0.5.0",
            )
            .unwrap(),
            remote_path: "/fixture/qshd".into(),
        };
        let result = InstallQuestion(Tty::at("/nonexistent/qsh-confirmation-fixture"))
            .approve(&offer, &cancel);
        assert!(
            matches!(
                result,
                Err(bringup::BringUpError::Ssh(ssh::SshError::Cancelled))
            ),
            "prompt cancellation must abort approval, not become a refusal or success"
        );
    }

    #[test]
    fn unreadable_stores_stop_foreground_and_background_before_ssh() {
        use std::os::unix::fs::PermissionsExt;
        for background in [false, true] {
            for system_fails in [false, true] {
                let home = tempfile::tempdir().unwrap();
                std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                let user = home.path().join("known_hosts");
                let system = home.path().join("ssh_known_hosts");
                let failed = if system_fails { &system } else { &user };
                std::fs::create_dir(failed).unwrap();
                // A trusted key cannot make an unavailable revocation store safe.
                let readable = if system_fails { &user } else { &system };
                std::fs::write(readable, "host.invalid ssh-ed25519 AQID\n").unwrap();
                std::fs::set_permissions(readable, std::fs::Permissions::from_mode(0o600)).unwrap();
                let known = KnownHosts::new(user.clone(), Some(system.clone()));
                let tty = Tty::at(home.path().join("no-tty"));
                let step = SshStep {
                    login: "test",
                    identity: None,
                    no_password: true,
                    agent: None,
                    ssh_dir: None,
                    known_hosts: &known,
                    tty: &tty,
                    background,
                    images: Arc::new(crate::releases::GitHubImages::new(
                        home.path().join("cache"),
                    )),
                };
                let route = ::connect::SshRoute {
                    port: 22,
                    knock: vec![],
                };
                let addr = ::connect::Address {
                    host: "host.invalid".into(),
                    qsh_port: 60022,
                    ssh: Some(route.clone()),
                };
                let started = std::cell::Cell::new(false);
                let cancel = knock::Cancel::new();
                let error = if background {
                    step.run_bound_observed(
                        &addr,
                        &route,
                        [7; 32],
                        &[vec![1, 2, 3]],
                        &cancel,
                        || started.set(true),
                    )
                    .unwrap_err()
                } else {
                    step.run_inner(&addr, &route, [7; 32], &cancel).unwrap_err()
                };
                assert!(
                    !started.get(),
                    "unreadable trust store must prevent SSH activity"
                );
                let message = format!("{error:?}");
                assert!(message.contains(&failed.display().to_string()), "{message}");
                assert!(message.contains("Is a directory"), "{message}");
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn background_missing_daemon_never_calls_image_source() {
        struct Spy(std::sync::atomic::AtomicUsize);
        impl bringup::ImageSource for Spy {
            fn load(
                &self,
                _: &bringup::ImageRequest,
                _: &bringup::InstallTiming,
                _: &knock::Cancel,
                _: &dyn bringup::BringUpObserver,
            ) -> Result<bringup::DaemonImage, bringup::ImageError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(bringup::ImageError::Download(
                    "must never load in background".into(),
                ))
            }
        }
        let home = tempfile::tempdir().unwrap();
        let (identity, public) = support_home::ssh_support::keygen_file("ed25519", home.path());
        let sb = support_home::Sandbox::start_with(&[public]);
        let known = KnownHosts::new(home.path().join("known_hosts"), None);
        let public = sb.sshd.host_public_key_line();
        let fields: Vec<_> = public.split_whitespace().collect();
        known
            .add(
                "127.0.0.1",
                sb.sshd.port,
                fields[0],
                &support_home::ssh_support::wire_of(&public),
            )
            .unwrap();
        let source = Arc::new(Spy(0.into()));
        let step = SshStep {
            login: &std::env::var("USER").unwrap(),
            identity: Some(&identity),
            no_password: true,
            agent: None,
            ssh_dir: None,
            known_hosts: &known,
            tty: &Tty::at("/nonexistent/qsh-background-tty"),
            background: true,
            images: source.clone(),
        };
        let route = ::connect::SshRoute {
            port: sb.sshd.port,
            knock: vec![],
        };
        let addr = ::connect::Address {
            host: "127.0.0.1".into(),
            qsh_port: 60022,
            ssh: Some(route.clone()),
        };
        let observed = std::cell::Cell::new(false);
        assert_eq!(
            step.run_bound_observed(&addr, &route, [7; 32], &[], &knock::Cancel::new(), || {
                observed.set(true)
            }),
            Err(SshStepError::NeedsPrompt)
        );
        assert!(
            !observed.get(),
            "an unbound route is not an active SSH attempt"
        );
        assert_eq!(
            step.run_bound(
                &addr,
                &route,
                [7; 32],
                &known.lookup("127.0.0.1", sb.sshd.port).unwrap().known,
                &knock::Cancel::new()
            ),
            Err(SshStepError::NeedsPrompt)
        );
        assert_eq!(source.0.load(Ordering::SeqCst), 0);
        assert!(std::fs::read_dir(sb.cache()).unwrap().next().is_none());
    }

    fn kinds(methods: &[ssh::AuthMethod]) -> Vec<String> {
        methods.iter().map(|m| format!("{m:?}")).collect()
    }

    #[test]
    fn the_plan_follows_openssh_order() {
        let files = vec![
            PathBuf::from("/h/.ssh/id_ed25519"),
            PathBuf::from("/h/.ssh/id_rsa"),
        ];
        let m = plan_methods(
            Some(Path::new("/k/mine")),
            Some(Path::new("/run/agent")),
            &files,
            false,
        );
        assert_eq!(
            kinds(&m),
            vec![
                "KeyFile(/k/mine)",
                "Agent(/run/agent)",
                "KeyFile(/h/.ssh/id_ed25519)",
                "KeyFile(/h/.ssh/id_rsa)",
                "KeyboardInteractive",
                "AskPassword",
                "AskPassword",
                "AskPassword",
            ]
        );
    }

    #[test]
    fn no_password_leaves_only_keys() {
        let m = plan_methods(None, None, &[PathBuf::from("/h/.ssh/id_ed25519")], true);
        assert_eq!(kinds(&m), vec!["KeyFile(/h/.ssh/id_ed25519)"]);
    }

    #[test]
    fn the_identity_file_is_not_offered_twice() {
        let files = vec![PathBuf::from("/h/.ssh/id_ed25519")];
        let m = plan_methods(Some(Path::new("/h/.ssh/id_ed25519")), None, &files, true);
        assert_eq!(kinds(&m), vec!["KeyFile(/h/.ssh/id_ed25519)"]);
    }

    #[test]
    fn default_key_files_are_the_ones_that_exist_in_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_rsa"), "x").unwrap();
        std::fs::write(dir.path().join("id_ed25519"), "x").unwrap();
        assert_eq!(
            default_key_files(dir.path()),
            vec![dir.path().join("id_ed25519"), dir.path().join("id_rsa")]
        );
    }

    fn info(key: &[u8]) -> ssh::HostKeyInfo {
        ssh::HostKeyInfo {
            key_type: "ssh-ed25519".into(),
            key: key.to_vec(),
            fingerprint: "SHA256:abc".into(),
        }
    }

    #[test]
    fn an_unknown_ssh_host_key_is_asked_about() {
        let e = ssh::SshError::UnknownHostKey(info(b"k"));
        assert!(matches!(
            judge_host_key(&e, &HostKeys::default(), "h", &KnownHosts::standard()),
            HostKeyVerdict::Ask(_)
        ));
    }

    #[test]
    fn a_changed_ssh_host_key_is_a_loud_failure() {
        let e = ssh::SshError::HostKeyChanged(info(b"k"));
        let store = KnownHosts::new(
            "custom directory/known_hosts".into(),
            Some("system directory/ssh_known_hosts".into()),
        );
        match judge_host_key(&e, &HostKeys::default(), "[h]:2222", &store) {
            HostKeyVerdict::Refuse(t) => {
                assert!(
                    t.starts_with("WARNING: the ssh host key of [h]:2222 has changed"),
                    "{t}"
                );
                assert!(!t.contains("~/.ssh/known_hosts"), "{t}");
                assert!(t.contains("custom directory/known_hosts"), "{t}");
                assert!(t.contains("system directory/ssh_known_hosts"), "{t}");
            }
            _ => panic!("expected Refuse"),
        }
    }

    #[test]
    fn a_revoked_ssh_host_key_is_refused_without_asking() {
        let keys = HostKeys {
            known: vec![],
            revoked: vec![b"k".to_vec()],
        };
        for e in [
            ssh::SshError::UnknownHostKey(info(b"k")),
            ssh::SshError::HostKeyChanged(info(b"k")),
        ] {
            match judge_host_key(&e, &keys, "h", &KnownHosts::standard()) {
                HostKeyVerdict::Refuse(t) => assert!(t.contains("@revoked"), "{t}"),
                _ => panic!("expected Refuse"),
            }
        }
    }

    #[test]
    fn a_background_ssh_prompter_answers_nothing_and_remembers_it_was_asked() {
        use ssh::AuthPrompter as _;
        let u = Unanswered::default();
        assert!(!u.asked());
        assert!(u.password("u", "h").is_none());
        assert!(u.asked());
        let u = Unanswered::default();
        assert!(u.passphrase(Path::new("/k")).is_none() && u.asked());
        let u = Unanswered::default();
        assert!(u
            .keyboard_interactive(
                "",
                "",
                &[ssh::Prompt {
                    text: "x".into(),
                    echo: false
                }]
            )
            .is_none());
        assert!(u.asked());
    }

    #[test]
    fn an_unknown_ssh_host_key_is_skipped_in_the_background() {
        let info = ssh::HostKeyInfo {
            key_type: "ssh-ed25519".into(),
            key: b"k".to_vec(),
            fingerprint: "SHA256:abc".into(),
        };
        assert_eq!(unknown_host_key(true, "h", &info), UnknownHostKey::Skip);
        assert!(
            matches!(unknown_host_key(false, "h", &info), UnknownHostKey::Ask(q) if q.contains("SHA256:abc"))
        );
    }

    #[test]
    fn other_errors_are_not_about_the_key() {
        let e = ssh::SshError::AuthFailed("no".into());
        assert!(matches!(
            judge_host_key(&e, &HostKeys::default(), "h", &KnownHosts::standard()),
            HostKeyVerdict::NotAboutTheKey
        ));
    }

    #[test]
    fn native_crypto_busy_retains_its_retry_classification() {
        let failure = ssh_failure(&ssh::SshError::CryptoBusy, false);
        assert_eq!(failure.cause, ::connect::SshFailureCause::CryptoBusy);
        assert!(!failure.local_network_hint);
        assert!(failure.why.contains("private-key workers are busy"));
    }

    fn unreachable(target: &str, kind: std::io::ErrorKind) -> ssh::SshError {
        ssh::SshError::Unreachable {
            target: target.parse().expect("addr"),
            kind,
            os_error: "No route to host (os error 65)".into(),
        }
    }

    /// Spec §4.2: the ssh step flags macOS's "no route" to a local address
    /// as a likely denied Local Network permission -- as data, the words
    /// stay the OS's own.
    #[test]
    fn no_route_to_a_local_address_on_macos_is_flagged() {
        let e = unreachable("192.168.0.200:22", std::io::ErrorKind::HostUnreachable);
        assert_eq!(
            ssh_failure(&e, true),
            ::connect::SshFailure {
                why: "192.168.0.200:22: No route to host (os error 65)".into(),
                local_network_hint: true,
                cause: ::connect::SshFailureCause::Other,
            }
        );
    }

    /// Anywhere else, to a public address, for another error or another
    /// kind of failure, nothing is flagged.
    #[test]
    fn otherwise_nothing_is_flagged() {
        let lan = unreachable("192.168.0.200:22", std::io::ErrorKind::HostUnreachable);
        assert!(!ssh_failure(&lan, false).local_network_hint);
        let public = unreachable("203.0.113.7:22", std::io::ErrorKind::HostUnreachable);
        assert!(!ssh_failure(&public, true).local_network_hint);
        let refused = unreachable("192.168.0.200:22", std::io::ErrorKind::ConnectionRefused);
        assert!(!ssh_failure(&refused, true).local_network_hint);
        let other = ssh::SshError::Connect("192.168.0.200:22 did not answer within 10s".into());
        assert!(!ssh_failure(&other, true).local_network_hint);
    }
}
