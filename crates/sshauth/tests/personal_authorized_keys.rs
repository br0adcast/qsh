//! Disposable generated keys test signed admission; no key authorizes a real service.
use ssh_key::{Algorithm, PrivateKey};
use sshauth::verify::AuthorizedKeysVerifier;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use transport::auth::{auth_challenge, AuthError, AuthRecord, AuthVerifier};

// The exact self-exec child must terminate before its TempDir can be removed,
// including wait errors and assertion unwinding. No process-global cwd changes.
struct RelativeChild {
    child: std::process::Child,
    terminal: bool,
    cleanup_wait_errors: usize,
    cleanup_receipt: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}
impl RelativeChild {
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.terminal = true;
                return Ok(status);
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relative authorization child did not finish",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}
impl Drop for RelativeChild {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        if let Err(error) = self.child.kill() {
            eprintln!(
                "relative authorization child termination failed; retaining custody: {error}"
            );
        }
        // No wait error (including ECHILD) proves this exact child's exit.
        // Retain the child and enclosing TempDir until terminal wait succeeds.
        let mut reported = false;
        loop {
            let result = if self.cleanup_wait_errors > 0 {
                self.cleanup_wait_errors -= 1;
                Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
            } else {
                self.child.wait()
            };
            match result {
                Ok(_) => {
                    self.terminal = true;
                    if let Some(receipt) = &self.cleanup_receipt {
                        receipt.fetch_or(2, std::sync::atomic::Ordering::SeqCst);
                    }
                    break;
                }
                Err(error) => {
                    if let Some(receipt) = &self.cleanup_receipt {
                        receipt.fetch_or(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    if !reported {
                        eprintln!("relative authorization child wait failed; retaining custody and retrying: {error}");
                        reported = true;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
    }
}
fn key() -> PrivateKey {
    PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .unwrap()
}
fn record(key: &PrivateKey, hash: &[u8; 32]) -> AuthRecord {
    let signature = signature::Signer::try_sign(key, &auth_challenge(hash)).unwrap();
    AuthRecord {
        public_key: sshauth::record::encode_public_key(key.public_key()).unwrap(),
        signature: sshauth::record::encode_signature(&signature).unwrap(),
        v2: None,
    }
}
fn mode(p: &Path, bits: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(bits)).unwrap();
}
fn dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn write(p: &Path, k: &PrivateKey) {
    std::fs::write(p, format!("{}\n", k.public_key().to_openssh().unwrap())).unwrap();
    mode(p, 0o644);
}
fn verify(p: PathBuf, k: &PrivateKey) -> Result<transport::auth::Principal, AuthError> {
    AuthorizedKeysVerifier::new(p, 1234, "fixture".into()).verify(
        &[37; 32],
        &record(k, &[37; 32]),
        [0; 16],
        "",
    )
}

#[test]
fn personal_authorized_keys_trusted_explicit_paths_and_aliases_authorize() {
    const CHILD: &str = "QSH_PERSONAL_KEYS_RELATIVE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let text = std::fs::read_to_string(path).unwrap();
        let k = PrivateKey::from_openssh(text).unwrap();
        assert!(verify(PathBuf::from("alias"), &k).is_ok());
        return;
    }
    let d = dir();
    let k = key();
    let p = d.path().join("keys");
    write(&p, &k);
    assert_eq!(verify(p.clone(), &k).unwrap().uid, 1234);
    let a = d.path().join("alias");
    symlink("keys", &a).unwrap();
    assert!(verify(a, &k).is_ok());
    let a = d.path().join("absolute");
    symlink(&p, &a).unwrap();
    assert!(verify(a, &k).is_ok());
    let parent = d.path().join("parent");
    symlink(d.path(), &parent).unwrap();
    assert!(verify(parent.join("keys"), &k).is_ok());
    let private = d.path().join("disposable-private");
    std::fs::write(
        &private,
        k.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    mode(&private, 0o600);
    let spawn = || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "personal_authorized_keys_trusted_explicit_paths_and_aliases_authorize",
                "--nocapture",
            ])
            .env(CHILD, &private)
            .current_dir(d.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut child = RelativeChild {
        child: spawn(),
        terminal: false,
        cleanup_wait_errors: 0,
        cleanup_receipt: None,
    };
    let status = child.wait();
    drop(child);
    assert!(status.unwrap().success());
    // Exercise cleanup during caught assertion unwinding with one transient
    // wait error. The same owned child must reach an actual terminal wait.
    let receipt = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cleanup = RelativeChild {
        child: spawn(),
        terminal: false,
        cleanup_wait_errors: 1,
        cleanup_receipt: Some(receipt.clone()),
    };
    let unwind = std::panic::catch_unwind(move || {
        let _cleanup = cleanup;
        panic!("owned relative fixture cleanup control");
    });
    assert!(unwind.is_err());
    assert_eq!(
        receipt.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "observed wait error followed by actual terminal wait"
    );
    assert!(
        d.path().exists(),
        "fixture retained through exact child cleanup"
    );
}
#[test]
fn personal_authorized_keys_unsafe_sources_never_produce_principal() {
    let d = dir();
    let k = key();
    let p = d.path().join("keys");
    write(&p, &k);
    let mut granted = Vec::new();
    for bits in [0o664, 0o646] {
        mode(&p, bits);
        if verify(p.clone(), &k).is_ok() {
            granted.push(format!("writable leaf {bits:o}"));
        }
    }
    mode(&p, 0o644);
    mode(d.path(), 0o775);
    if verify(p.clone(), &k).is_ok() {
        granted.push("writable parent 775".into());
    }
    mode(d.path(), 0o700);
    assert!(granted.is_empty(), "unsafe sources authorized: {granted:?}");
}
#[test]
fn personal_authorized_keys_oversized_valid_prefix_never_authorizes() {
    let d = dir();
    let k = key();
    let p = d.path().join("keys");
    let mut text = format!("{}\n#", k.public_key().to_openssh().unwrap()).into_bytes();
    text.resize(1024 * 1024, b'x');
    std::fs::write(&p, &text).unwrap();
    mode(&p, 0o644);
    assert!(verify(p.clone(), &k).is_ok());
    text.push(b'x');
    std::fs::write(&p, text).unwrap();
    assert!(verify(p, &k).is_err(), "oversized valid prefix authorized");
}
#[test]
fn personal_authorized_keys_each_attempt_revalidates_replaced_authority() {
    let d = dir();
    let k = key();
    let p = d.path().join("keys");
    write(&p, &k);
    let v = AuthorizedKeysVerifier::new(p.clone(), 1234, "fixture".into());
    let r = record(&k, &[37; 32]);
    assert!(v.verify(&[37; 32], &r, [0; 16], "").is_ok());
    std::fs::rename(&p, d.path().join("old")).unwrap();
    write(&p, &k);
    mode(&p, 0o666);
    assert!(v.verify(&[37; 32], &r, [0; 16], "").is_err());
}
#[test]
fn personal_authorized_keys_bad_signature_fails_before_file_lookup() {
    let d = dir();
    let k = key();
    let v = AuthorizedKeysVerifier::new(d.path().join("absent"), 1234, "fixture".into());
    assert_eq!(
        v.verify(&[38; 32], &record(&k, &[37; 32]), [0; 16], ""),
        Err(AuthError::BadSignature)
    );
}
