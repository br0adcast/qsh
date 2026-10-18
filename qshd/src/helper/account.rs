//! Resolving a login name to the account behind it.
//!
//! In the privileged helper, everything here is done BEFORE the fork that
//! starts a channel -- the supplementary group list in particular, because
//! `initgroups` builds it with `malloc` and the child between `fork` and
//! `exec` may not allocate. [`lookup`] itself is called while a client is
//! being verified, never from that child.
//!
//! The worker calls [`lookup`] too, once, for its own account
//! (`super::drop_worker_privileges`). That call is on the far side of a
//! DIFFERENT fork -- the helper/worker split -- and is an ordinary call in
//! an ordinary process: nothing is waiting to `exec`, the worker is still
//! single-threaded, and it may allocate freely. The rule above is about the
//! channel fork alone.

use std::fmt;
use std::path::PathBuf;

use nix::unistd::{Gid, Uid};

/// An account, as the helper needs it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Account {
    pub uid: Uid,
    pub gid: Gid,
    pub name: String,
    pub home: PathBuf,
    pub shell: PathBuf,
    /// NSS/authorization baseline, including the primary group, in the order
    /// `getgrouplist` returned them. PAM session credentials are monitor-local
    /// and must not change this authorization context.
    pub groups: Vec<Gid>,
}

/// Why a name did not become an account.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AccountError {
    /// Not a usable login name at all.
    BadName,
    /// `getpwnam` found nothing.
    NoSuchAccount,
    /// The name resolved, but the groups could not be listed.
    Groups(String),
    /// The platform refused to answer.
    Backend(String),
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountError::BadName => write!(f, "not a usable login name"),
            AccountError::NoSuchAccount => write!(f, "no such account"),
            AccountError::Groups(msg) => write!(f, "could not list the account's groups: {msg}"),
            AccountError::Backend(msg) => write!(f, "the platform refused to answer: {msg}"),
        }
    }
}

impl std::error::Error for AccountError {}

/// Resolve `name`. The name is re-checked here even though the seam's codec
/// already refuses an unusable one: a check that exists in one place only is
/// a check that will one day be moved away from the thing it protects.
pub fn lookup(name: &str) -> Result<Account, AccountError> {
    if name.is_empty() || name.len() > 255 || name.contains('/') || name.contains('\0') {
        return Err(AccountError::BadName);
    }
    let user = nix::unistd::User::from_name(name)
        .map_err(|e| AccountError::Backend(e.to_string()))?
        .ok_or(AccountError::NoSuchAccount)?;
    let groups = nix::unistd::getgrouplist(
        &std::ffi::CString::new(name).map_err(|_| AccountError::BadName)?,
        user.gid,
    )
    .map_err(|e| AccountError::Groups(e.to_string()))?;
    Ok(Account {
        uid: user.uid,
        gid: user.gid,
        name: user.name,
        home: user.dir,
        shell: user.shell,
        groups,
    })
}

/// Expand an authorized-keys template. `%h` is the home directory from
/// `passwd`, `%u` the login name -- the same two `sshd` uses, and no others:
/// an expansion the operator cannot predict is one they cannot audit.
pub fn expand_template(template: &str, account: &Account) -> PathBuf {
    PathBuf::from(
        template
            .replace("%h", &account.home.to_string_lossy())
            .replace("%u", &account.name),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account this test process runs as is the one account we can be sure
    /// exists on any machine the suite runs on.
    #[test]
    fn an_existing_account_resolves_to_its_passwd_entry() {
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .expect("passwd")
            .expect("the current account exists");
        let account = lookup(&me.name).expect("resolves");
        assert_eq!(account.uid, me.uid);
        assert_eq!(account.gid, me.gid);
        assert_eq!(account.name, me.name);
        assert_eq!(account.home, me.dir);
        assert_eq!(account.shell, me.shell);
        assert!(
            account.groups.contains(&me.gid),
            "the primary group belongs in the supplementary list too, as initgroups does it"
        );
    }

    #[test]
    fn an_unknown_account_is_refused() {
        assert!(matches!(
            lookup("definitely-no-such-account-here"),
            Err(AccountError::NoSuchAccount)
        ));
    }

    /// The name reaches `getpwnam`, so it must not be able to mean anything but
    /// a name. The codec already refuses these, and so does this: a check in one
    /// place only is a check that moves away.
    #[test]
    fn a_name_that_is_not_a_name_is_refused() {
        for bad in ["", "root/../alice", "ali\0ce"] {
            assert!(matches!(lookup(bad), Err(AccountError::BadName)), "{bad:?}");
        }
    }

    #[test]
    fn the_template_expands_both_placeholders() {
        let account = Account {
            uid: Uid::from_raw(1000),
            gid: Gid::from_raw(1000),
            name: "alice".to_string(),
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/sh"),
            groups: Vec::new(),
        };
        assert_eq!(
            expand_template("%h/.ssh/authorized_keys", &account),
            PathBuf::from("/home/alice/.ssh/authorized_keys")
        );
        assert_eq!(
            expand_template("/etc/qshd/keys/%u", &account),
            PathBuf::from("/etc/qshd/keys/alice")
        );
    }

    /// `drop_worker_privileges` wraps every `AccountError` with `.with_context`,
    /// which requires `std::error::Error` (and therefore `Display`) -- this is
    /// that requirement, exercised directly rather than only through the
    /// caller that needs it.
    #[test]
    fn account_error_implements_the_error_trait() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<AccountError>();
        assert_eq!(AccountError::BadName.to_string(), "not a usable login name");
    }
}
