//! Real credential and authorization-object checks. Run this single sequential
//! test only in a disposable root container with QSHD_TEST_DISPOSABLE_HOST=1.
//! Never run it with host sudo: effective identity changes affect every thread.

#![cfg(feature = "system")]

use std::os::unix::fs::{chown, PermissionsExt};
use std::path::Path;

use nix::unistd::{Gid, Uid};
use qshd::helper::account::Account;
use qshd::helper::authorized::{read_for, AuthorizedError};

fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}

fn identity() -> (Uid, Gid, Vec<Gid>) {
    let mut groups = nix::unistd::getgroups().unwrap();
    groups.sort_unstable_by_key(|group| group.as_raw());
    (Uid::effective(), Gid::effective(), groups)
}

fn checked_read(account: &Account, path: &Path) -> Result<String, AuthorizedError> {
    let before = identity();
    let result = read_for(account, path.to_str().unwrap());
    assert_eq!(
        identity(),
        before,
        "restore uid, gid and supplementary groups"
    );
    result
}

fn refused(account: &Account, path: &Path, reason: &str) {
    let err = checked_read(account, path).expect_err("unsafe authorization must be refused");
    assert!(matches!(err, AuthorizedError::Read { .. }), "{err}");
    assert!(err.to_string().contains(reason), "expected {reason}: {err}");
}

#[test]
fn the_effective_account_is_restored_even_when_the_read_fails() {
    if !Uid::effective().is_root()
        || std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() != Ok("1")
    {
        eprintln!("SKIPPED the_effective_account_is_restored_even_when_the_read_fails: requires root and QSHD_TEST_DISPOSABLE_HOST=1 in a disposable container");
        return;
    }
    // /var/lib is root-owned and not writable by other principals. A private
    // child of /tmp would conceal leaf checks behind an unsafe ancestor.
    let dir = tempfile::Builder::new()
        .prefix("qshd-keys-")
        .tempdir_in("/var/lib")
        .unwrap();
    mode(dir.path(), 0o755);
    let account = Account {
        uid: Uid::from_raw(61001),
        gid: Gid::from_raw(61001),
        groups: vec![Gid::from_raw(61001), Gid::from_raw(61003)],
        name: "qshd-fixture-alice".into(),
        home: dir.path().into(),
        shell: "/bin/sh".into(),
    };
    let path = dir.path().join("keys");
    std::fs::write(&path, "safe keys").unwrap();
    mode(&path, 0o644);
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "root-owned readable store"
    );
    mode(dir.path(), 0o711);
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "search-only parent"
    );
    mode(dir.path(), 0o755);

    // This must reach the leaf's kernel permission check, not an ancestor policy
    // refusal. Retaining root's effective gid would incorrectly allow this read.
    mode(&path, 0o640);
    refused(&account, &path, "Permission denied");
    chown(&path, Some(0), Some(61003)).unwrap();
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "supplementary group grants read"
    );
    chown(&path, Some(61001), Some(61001)).unwrap();
    mode(&path, 0o600);
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "account-private keys"
    );

    for bits in [0o620, 0o602] {
        mode(&path, bits);
        refused(&account, &path, "writable by group or others");
        mode(&path, 0o600);
        assert_eq!(checked_read(&account, &path).unwrap(), "safe keys");
    }
    chown(&path, Some(61002), Some(61002)).unwrap();
    mode(&path, 0o644);
    refused(&account, &path, "untrusted owner");
    chown(&path, Some(61001), Some(61001)).unwrap();

    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    mode(&parent, 0o755);
    let nested = parent.join("keys");
    std::fs::write(&nested, "nested keys").unwrap();
    mode(&nested, 0o644);
    assert_eq!(checked_read(&account, &nested).unwrap(), "nested keys");
    chown(&parent, Some(61002), Some(61002)).unwrap();
    refused(&account, &nested, "untrusted owner");
    chown(&parent, Some(61001), Some(61001)).unwrap();
    for bits in [0o775, 0o757] {
        mode(&parent, bits);
        refused(&account, &nested, "writable by group or others");
        mode(&parent, 0o755);
        assert_eq!(checked_read(&account, &nested).unwrap(), "nested keys");
    }
    mode(dir.path(), 0o777);
    refused(&account, &nested, "writable by group or others");
    mode(dir.path(), 0o755);

    assert_eq!(
        checked_read(&account, &dir.path().join("missing")).unwrap(),
        ""
    );
    refused(&account, &parent, "not a regular file");
    refused(&account, Path::new("/dev/zero"), "not a regular file");
    let link = dir.path().join("linked-keys");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(checked_read(&account, &link).is_err());
    std::fs::write(&path, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    refused(&account, &path, "larger than");
    std::fs::write(&path, [0xff]).unwrap();
    refused(&account, &path, "invalid utf-8");
    mode(&path, 0o000);
    refused(&account, &path, "Permission denied");
    let unsafe_dir = tempfile::tempdir().unwrap();
    mode(unsafe_dir.path(), 0o755);
    let unsafe_path = unsafe_dir.path().join("keys");
    std::fs::write(&unsafe_path, "keys").unwrap();
    refused(&account, &unsafe_path, "writable by group or others");
}

// This personal-mode fixture never changes the parent process's identity. The
// generated signer exists only in memory; the child receives a public proof.
mod personal {
    use super::mode;
    use ssh_key::{Algorithm, PrivateKey};
    use sshauth::verify::AuthorizedKeysVerifier;
    use std::fs::{File, Metadata};
    use std::io::{self, Read};
    use std::os::unix::fs::{chown, lchown, MetadataExt};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};
    use transport::auth::{
        auth_challenge, encode_auth_record, parse_auth_record, AuthError, AuthRecord, AuthVerifier,
    };

    pub(super) const NAME: &str =
        "personal_authorized_keys_enforces_real_account_and_root_ownership";
    pub(super) const ROLE: &str = "QSH_PERSONAL_AUTHORITY_CHILD";
    const UID: u32 = 61001;
    const FOREIGN: u32 = 61002;
    const CHALLENGE: [u8; 32] = [73; 32];

    // Retain exact child custody, including assertion/error unwinding. A timeout
    // is a test failure; only terminal wait permits fixture directory release.
    struct OwnedChild {
        child: Child,
        terminal: bool,
    }
    impl OwnedChild {
        fn wait(&mut self) -> io::Result<ExitStatus> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = self.child.try_wait()? {
                    self.terminal = true;
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "personal authority child did not finish",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.terminal {
                return;
            }
            if let Err(error) = self.child.kill() {
                eprintln!(
                    "personal authority child termination failed; retaining custody: {error}"
                );
            }
            // The result deadline fails the test; it cannot prove cleanup.
            // Even ECHILD is an error here, not terminal evidence to release.
            let mut reported = false;
            loop {
                match self.child.wait() {
                    Ok(_) => {
                        self.terminal = true;
                        break;
                    }
                    Err(error) => {
                        if !reported {
                            eprintln!("personal authority child wait failed; retaining child and fixture and retrying: {error}");
                            reported = true;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        }
    }
    fn owned(path: &Path, uid: u32, bits: u32) {
        chown(path, Some(uid), Some(uid)).unwrap();
        mode(path, bits);
    }
    fn metadata(path: &Path) -> Metadata {
        std::fs::symlink_metadata(path).unwrap()
    }
    pub(super) fn child() {
        let parent = std::env::var("QSH_PERSONAL_AUTHORITY_PARENT")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert_eq!(nix::unistd::getppid().as_raw() as u32, parent);
        assert_eq!(nix::unistd::Uid::effective().as_raw(), UID);
        assert_eq!(nix::unistd::Gid::effective().as_raw(), UID);
        assert!(nix::unistd::getgroups()
            .unwrap()
            .iter()
            .all(|g| g.as_raw() != 0));
        let root =
            std::path::PathBuf::from(std::env::var_os("QSH_PERSONAL_AUTHORITY_ROOT").unwrap());
        assert_eq!(root.parent(), Some(Path::new("/var/lib")));
        assert!(root
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .starts_with(b"qshd-personal-keys-"));
        let m = metadata(&root);
        assert!(m.is_dir());
        assert_eq!(m.uid(), 0);
        assert_eq!(m.mode() & 0o7777, 0o755);
        let proof = root.join("proof");
        let m = metadata(&proof);
        assert!(m.is_file());
        assert_eq!(m.uid(), 0);
        assert_eq!(m.mode() & 0o777, 0o644);
        assert!(m.len() <= 16384);
        let mut bytes = Vec::new();
        File::open(&proof)
            .unwrap()
            .take(16385)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 16384);
        let record = parse_auth_record(&bytes).unwrap();
        let verify = |path: &str, principal_uid: u32| {
            AuthorizedKeysVerifier::new(root.join(path), principal_uid, "fixture-account".into())
                .verify(&CHALLENGE, &record, [0; 16], "")
        };
        for path in [
            "root-readable",
            "account-private",
            "root-alias",
            "account-alias",
            "account-search/keys",
            "root-search/keys",
            "sticky/keys",
        ] {
            let principal = verify(path, UID).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(principal.uid, UID);
            assert_eq!(principal.name, "fixture-account");
        }
        for path in ["root-private", "root-group-only"] {
            let err = verify(path, UID).unwrap_err();
            assert!(matches!(err, AuthError::Backend(_)));
            assert!(
                err.to_string().contains("Permission denied"),
                "{path}: {err}"
            );
        }
        for path in [
            "foreign-file",
            "foreign-parent/keys",
            "foreign-alias",
            "writable-file",
            "writable-parent/keys",
            "unsafe-target-alias",
        ] {
            assert!(verify(path, UID).is_err(), "{path} authorized");
        }
        assert!(
            verify("foreign-file", FOREIGN).is_err(),
            "constructor UID cannot enlarge filesystem authority"
        );
        assert_eq!(
            verify("root-readable", FOREIGN).unwrap().uid,
            FOREIGN,
            "Principal identity contract remains caller-supplied"
        );
        println!("validated personal account/root/foreign authorization authority");
    }
    pub(super) fn parent() {
        let dir = tempfile::Builder::new()
            .prefix("qshd-personal-keys-")
            .tempdir_in("/var/lib")
            .unwrap();
        mode(dir.path(), 0o755);
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap();
        let line = format!("{}\n", key.public_key().to_openssh().unwrap());
        let sig = signature::Signer::try_sign(&key, &auth_challenge(&CHALLENGE)).unwrap();
        let record = AuthRecord {
            public_key: sshauth::record::encode_public_key(key.public_key()).unwrap(),
            signature: sshauth::record::encode_signature(&sig).unwrap(),
            v2: None,
        };
        let proof = dir.path().join("proof");
        std::fs::write(&proof, encode_auth_record(&record).unwrap()).unwrap();
        mode(&proof, 0o644);
        for (name, uid, bits) in [
            ("root-readable", 0, 0o644),
            ("root-private", 0, 0o400),
            ("root-group-only", 0, 0o640),
            ("account-private", UID, 0o600),
            ("foreign-file", FOREIGN, 0o644),
            ("writable-file", UID, 0o664),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, &line).unwrap();
            owned(&path, uid, bits);
        }
        for (name, uid, bits) in [
            ("foreign-parent", FOREIGN, 0o755),
            ("writable-parent", UID, 0o775),
            ("account-search", UID, 0o111),
            ("root-search", 0, 0o711),
            ("sticky", 0, 0o1777),
        ] {
            let path = dir.path().join(name);
            std::fs::create_dir(&path).unwrap();
            let leaf = path.join("keys");
            std::fs::write(&leaf, &line).unwrap();
            owned(&leaf, UID, 0o644);
            owned(&path, uid, bits);
        }
        for (name, target, uid) in [
            ("root-alias", "root-readable", 0),
            ("account-alias", "account-private", UID),
            ("foreign-alias", "root-readable", FOREIGN),
            ("unsafe-target-alias", "writable-file", 0),
        ] {
            let path = dir.path().join(name);
            std::os::unix::fs::symlink(target, &path).unwrap();
            lchown(&path, Some(uid), Some(uid)).unwrap();
        }
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        owned(&home, UID, 0o700);
        for name in ["config", "cache"] {
            let p = home.join(name);
            std::fs::create_dir(&p).unwrap();
            owned(&p, UID, 0o700);
        }
        let output = File::create(dir.path().join("child-output")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(ROLE, "1")
            .env(
                "QSH_PERSONAL_AUTHORITY_PARENT",
                std::process::id().to_string(),
            )
            .env("QSH_PERSONAL_AUTHORITY_ROOT", dir.path())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("HISTFILE", "/dev/null")
            .uid(UID)
            .gid(UID)
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let mut child = OwnedChild {
            child,
            terminal: false,
        };
        let result = child.wait();
        drop(child);
        let mut output = String::new();
        File::open(dir.path().join("child-output"))
            .unwrap()
            .take(65537)
            .read_to_string(&mut output)
            .unwrap();
        assert!(output.len() <= 65536, "child output exceeded bound");
        assert!(
            result.unwrap().success(),
            "personal authority child failed: {output}"
        );
        assert!(output.contains("validated personal account/root/foreign authorization authority"));
        // Never echo nested libtest control/summary lines into the root tier.
        println!("validated personal account/root/foreign authorization authority");
    }
}

#[test]
fn personal_authorized_keys_enforces_real_account_and_root_ownership() {
    if std::env::var_os(personal::ROLE).as_deref() == Some(std::ffi::OsStr::new("1")) {
        personal::child();
        return;
    }
    if !Uid::effective().is_root()
        || std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() != Ok("1")
    {
        eprintln!("SKIPPED personal_authorized_keys_enforces_real_account_and_root_ownership: requires root and QSHD_TEST_DISPOSABLE_HOST=1 in a disposable container");
        return;
    }
    personal::parent();
}
