//! Runs only metadata/hash/publication commands in owned temporary trees.
//! The candidate command is intercepted; candidate bytes are never executed.
use super::*;
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicUsize,
};

fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}
struct Hooks {
    loads: AtomicUsize,
    approvals: AtomicUsize,
}
impl crate::ImageSource for Hooks {
    fn load(
        &self,
        request: &ImageRequest,
        _: &crate::InstallTiming,
        _: &knock::Cancel,
        _: &dyn BringUpObserver,
    ) -> Result<DaemonImage, ImageError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let bytes: Arc<[u8]> = Arc::from(&b"owned fixture; never execute"[..]);
        Ok(DaemonImage {
            request: request.clone(),
            size: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        })
    }
}
impl crate::InstallApproval for Hooks {
    fn approve(&self, _: &InstallOffer, _: &knock::Cancel) -> Result<bool, BringUpError> {
        self.approvals.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}
impl BringUpObserver for Hooks {
    fn on_progress(&self, _: BringUpProgress) {}
}
fn hooks() -> (Arc<Hooks>, BringUpHooks) {
    let h = Arc::new(Hooks {
        loads: 0.into(),
        approvals: 0.into(),
    });
    (
        h.clone(),
        BringUpHooks {
            source: Some(h.clone()),
            approval: h.clone(),
            observer: h,
            timing: crate::InstallTiming::default(),
        },
    )
}
#[derive(Clone, Copy)]
enum VerificationFault {
    WrongDigest,
    MissingTool,
    ExtraRecord,
    Warning,
}
struct Fixture {
    root: tempfile::TempDir,
    found: Option<PathBuf>,
    cached: Option<PathBuf>,
    commands: Vec<(String, String)>,
    uploads: usize,
    cancel_after_trust: bool,
    poison_path: Option<PathBuf>,
    verification_fault: Option<VerificationFault>,
    temporary: Option<(String, Arc<AtomicBool>)>,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        mode(root.path(), 0o700);
        Self {
            root,
            found: None,
            cached: None,
            commands: vec![],
            uploads: 0,
            cancel_after_trust: false,
            poison_path: None,
            verification_fault: None,
            temporary: None,
        }
    }
    fn daemon(&mut self, permissions: u32) -> PathBuf {
        let p = self.root.path().join("qshd");
        fs::write(&p, b"unused custom build").unwrap();
        mode(&p, permissions);
        self.found = Some(p.clone());
        p
    }
    fn final_path(&self) -> PathBuf {
        self.root.path().join(".cache/qsh").join(
            crate::Platform::from_uname("Linux", std::env::consts::ARCH)
                .unwrap()
                .file_name("0.5.0"),
        )
    }
    fn run(
        &mut self,
        policy: InstallPolicy,
        hooks: BringUpHooks,
        cancel: &knock::Cancel,
    ) -> Result<crate::Ready, BringUpError> {
        on_session(
            self,
            "fixture".into(),
            60022,
            [7; 32],
            "fixture.invalid".into(),
            "fixture".into(),
            22,
            policy,
            hooks,
            cancel,
        )
    }
    fn starts(&self) -> usize {
        self.commands
            .iter()
            .filter(|(what, _)| what == "qshd transport-ensure")
            .count()
    }
}
impl Remote for Fixture {
    fn command(
        &mut self,
        what: &str,
        script: &str,
        _: Duration,
        cancel: &knock::Cancel,
    ) -> Result<exec::Output, BringUpError> {
        check_cancel(cancel)?;
        self.commands.push((what.into(), script.into()));
        if what == "the qshd lookup" {
            let found = self
                .found
                .as_ref()
                .map_or(String::new(), |p| format!("path {}\n", p.display()));
            let cached = self
                .cached
                .as_ref()
                .map_or(String::new(), |p| format!("cached {}\n", p.display()));
            return Ok(exec::test_support::output(
                0,
                &format!(
                    "os Linux\narch {}\nhome {}\n{found}{cached}",
                    std::env::consts::ARCH,
                    self.root.path().display()
                ),
            ));
        }
        if what == "qshd transport-ensure" {
            return Ok(exec::test_support::output(0,"server-pubkey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nTRANSPORT-READY {\"version\":\"custom-actual\",\"ports\":[60022]}\n"));
        }
        let mut command = Command::new("/bin/sh");
        if let Some(path) = &self.poison_path {
            command.env("PATH", path);
        }
        let output = command
            .arg("-c")
            .arg(script)
            .env("HOME", self.root.path())
            .env("XDG_CACHE_HOME", self.root.path().join("xdg-cache"))
            .env("XDG_CONFIG_HOME", self.root.path().join("xdg-config"))
            .env("HISTFILE", "/dev/null")
            .output()
            .unwrap();
        if self.cancel_after_trust && what == "qshd path trust" {
            cancel.cancel();
        }
        let code = output.status.code().unwrap_or(-1);
        let mut stdout = String::from_utf8(output.stdout).unwrap();
        let mut stderr = String::from_utf8(output.stderr).unwrap();
        if what == "qshd verification" {
            match self.verification_fault {
                Some(VerificationFault::MissingTool) => {
                    return Ok(exec::test_support::output_with_stderr(
                        127,
                        "",
                        "hash utility unavailable",
                    ))
                }
                Some(VerificationFault::WrongDigest) if code == 0 => {
                    stdout = format!(
                        "{}\n{}  file\n",
                        stdout.lines().next().unwrap(),
                        "0".repeat(64)
                    );
                }
                Some(VerificationFault::ExtraRecord) if code == 0 => {
                    stdout.push_str("unexpected-record\n")
                }
                Some(VerificationFault::Warning) => stderr.push_str("harmless-hash-warning\n"),
                _ => {}
            }
        }
        Ok(exec::test_support::output_with_stderr(
            code, &stdout, &stderr,
        ))
    }
    fn upload(
        &mut self,
        path: &str,
        image: &DaemonImage,
        _: &BringUpHooks,
        owned: Arc<AtomicBool>,
        _: Instant,
        cancel: &knock::Cancel,
    ) -> Result<(), BringUpError> {
        check_cancel(cancel)?;
        self.uploads += 1;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&image.bytes).unwrap();
        owned.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn temporary(&mut self, value: Option<(String, Arc<AtomicBool>)>) {
        self.temporary = value;
    }
}
fn bundled() -> InstallPolicy {
    InstallPolicy::EnsureBundled {
        version: "0.5.0".into(),
    }
}
#[test]
fn unsafe_found_is_verify_without_execution_installation_or_approval() {
    for policy in [
        InstallPolicy::ExistingOnly,
        InstallPolicy::RestartOnly,
        InstallPolicy::AskIfMissing {
            version: "0.5.0".into(),
        },
    ] {
        let mut f = Fixture::new();
        f.daemon(0o777);
        let (h, hooks) = hooks();
        let result = f.run(policy, hooks, &knock::Cancel::new());
        assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
        assert_eq!(f.starts(), 0);
        assert_eq!(f.uploads, 0);
        assert_eq!(h.loads.load(Ordering::SeqCst), 0);
        assert_eq!(h.approvals.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn trusted_custom_is_canonical_and_retains_actual_ready_version_without_image() {
    let mut f = Fixture::new();
    let path = f.daemon(0o700);
    let link = f.root.path().join("custom");
    std::os::unix::fs::symlink("qshd", &link).unwrap();
    f.found = Some(link);
    let (h, mut hooks) = hooks();
    hooks.source = None;
    let ready = f
        .run(InstallPolicy::RestartOnly, hooks, &knock::Cancel::new())
        .unwrap();
    assert_eq!(ready.version, "custom-actual");
    assert_eq!(h.loads.load(Ordering::SeqCst), 0);
    let script = &f
        .commands
        .iter()
        .find(|(what, _)| what == "qshd transport-ensure")
        .unwrap()
        .1;
    assert!(script.starts_with(&shell::quote(path.to_str().unwrap())));
    assert!(script.ends_with(" --restart-only"));
}
#[test]
fn managed_final_symlink_is_refused_before_hash_chmod_or_upload() {
    let mut f = Fixture::new();
    let target = f.daemon(0o700);
    fs::create_dir_all(f.final_path().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, f.final_path()).unwrap();
    let (_, hooks) = hooks();
    let result = f.run(bundled(), hooks, &knock::Cancel::new());
    assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
    assert_eq!(f.uploads, 0);
    assert_eq!(f.starts(), 0);
    assert!(!f.commands.iter().any(|(_, s)| s.contains("sha256sum")));
}
#[test]
fn cancellation_after_trust_stops_before_ensure() {
    let mut f = Fixture::new();
    f.daemon(0o700);
    f.cancel_after_trust = true;
    let (_, hooks) = hooks();
    let result = f.run(InstallPolicy::ExistingOnly, hooks, &knock::Cancel::new());
    assert!(
        matches!(result, Err(BringUpError::Ssh(ssh::SshError::Cancelled))),
        "{result:?}"
    );
    assert_eq!(f.starts(), 0);
}
#[test]
fn bundled_creates_only_checked_missing_directories_and_ignores_unsafe_discovery() {
    let mut f = Fixture::new();
    f.daemon(0o777);
    let (h, hooks) = hooks();
    let ready = f.run(bundled(), hooks, &knock::Cancel::new()).unwrap();
    assert_eq!(ready.version, "custom-actual");
    assert_eq!(h.loads.load(Ordering::SeqCst), 1);
    assert_eq!(h.approvals.load(Ordering::SeqCst), 0);
    assert_eq!(f.uploads, 1);
    assert_eq!(
        fs::read(f.final_path()).unwrap(),
        b"owned fixture; never execute"
    );
    for path in [
        f.root.path().join(".cache"),
        f.root.path().join(".cache/qsh"),
        f.final_path(),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert!(!f.commands.iter().any(|(_, s)| s.contains("mkdir -p")));
    let upload = f
        .commands
        .iter()
        .position(|(what, _)| what == "qshd publication")
        .unwrap();
    assert!(f.commands[..upload]
        .iter()
        .any(|(what, _)| what == "qshd path trust"));
}
#[test]
fn safe_cache_directory_link_and_private_writable_cache_use_canonical_destination() {
    let mut f = Fixture::new();
    fs::create_dir(f.root.path().join(".cache")).unwrap();
    let actual = f.root.path().join("owned cache");
    fs::create_dir(&actual).unwrap();
    mode(&actual, 0o770);
    std::os::unix::fs::symlink("../owned cache", f.root.path().join(".cache/qsh")).unwrap();
    let (_, hooks) = hooks();
    f.run(bundled(), hooks, &knock::Cancel::new()).unwrap();
    assert_eq!(f.uploads, 1);
    assert_eq!(
        fs::read(f.final_path()).unwrap(),
        b"owned fixture; never execute"
    );
    let ensure = &f
        .commands
        .iter()
        .find(|(what, _)| what == "qshd transport-ensure")
        .unwrap()
        .1;
    assert!(ensure.starts_with(&shell::quote(
        actual
            .join(f.final_path().file_name().unwrap())
            .to_str()
            .unwrap()
    )));
    assert!(fs::read_dir(actual).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".qshd-")));
}
#[test]
fn safe_mismatching_destination_is_replaced_but_writable_destination_is_not_repaired() {
    for permissions in [0o600, 0o777] {
        let mut f = Fixture::new();
        fs::create_dir_all(f.final_path().parent().unwrap()).unwrap();
        fs::write(f.final_path(), b"old bytes").unwrap();
        mode(&f.final_path(), permissions);
        let (_, hooks) = hooks();
        let result = f.run(bundled(), hooks, &knock::Cancel::new());
        if permissions == 0o600 {
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(f.uploads, 1);
            assert_eq!(
                fs::read(f.final_path()).unwrap(),
                b"owned fixture; never execute"
            );
        } else {
            assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
            assert_eq!(f.uploads, 0);
            assert_eq!(fs::read(f.final_path()).unwrap(), b"old bytes");
            assert_eq!(
                fs::metadata(f.final_path()).unwrap().permissions().mode() & 0o777,
                0o777
            );
            assert!(!f.commands.iter().any(|(_, s)| s.contains("sha256sum")));
        }
    }
}
#[test]
fn matching_bundled_file_is_verified_without_upload() {
    let mut f = Fixture::new();
    fs::create_dir_all(f.final_path().parent().unwrap()).unwrap();
    fs::write(f.final_path(), b"owned fixture; never execute").unwrap();
    mode(&f.final_path(), 0o600);
    let (_, hooks) = hooks();
    f.run(bundled(), hooks, &knock::Cancel::new()).unwrap();
    assert_eq!(f.uploads, 0);
    assert_eq!(
        fs::metadata(f.final_path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn misleading_cache_name_is_only_a_ranking_hint_and_unsafe_selected_cache_never_falls_back() {
    for permissions in [0o700, 0o777] {
        let mut f = Fixture::new();
        f.daemon(0o700);
        let cached = f.root.path().join(
            crate::Platform::from_uname("Linux", std::env::consts::ARCH)
                .unwrap()
                .file_name("999.0.0"),
        );
        fs::write(&cached, b"custom build never execute").unwrap();
        mode(&cached, permissions);
        f.cached = Some(cached);
        let (h, hooks) = hooks();
        let result = f.run(
            InstallPolicy::AskIfMissing {
                version: "0.5.0".into(),
            },
            hooks,
            &knock::Cancel::new(),
        );
        if permissions == 0o700 {
            assert_eq!(result.unwrap().version, "custom-actual");
            assert_eq!(f.starts(), 1);
        } else {
            assert!(matches!(result, Err(BringUpError::Verify(_))));
            assert_eq!(f.starts(), 0);
        }
        assert_eq!(h.loads.load(Ordering::SeqCst), 0);
        assert_eq!(h.approvals.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn managed_install_uses_system_utilities_independent_of_candidate_path() {
    let mut f = Fixture::new();
    let poison = f.root.path().join("poison-path");
    fs::create_dir(&poison).unwrap();
    for name in [
        "stat",
        "id",
        "readlink",
        "mkdir",
        "chmod",
        "mv",
        "rm",
        "wc",
        "sha256sum",
    ] {
        let path = poison.join(name);
        fs::write(&path, b"#!/bin/sh\nexit 88\n").unwrap();
        mode(&path, 0o700);
    }
    f.poison_path = Some(poison);
    let (_, hooks) = hooks();
    let result = f.run(bundled(), hooks, &knock::Cancel::new());
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        fs::read(f.final_path()).unwrap(),
        b"owned fixture; never execute"
    );
}

#[test]
fn verification_wrong_digest_keeps_old_file_and_cleans_owned_upload() {
    let mut f = Fixture::new();
    fs::create_dir_all(f.final_path().parent().unwrap()).unwrap();
    fs::write(f.final_path(), b"old daemon").unwrap();
    mode(&f.final_path(), 0o600);
    f.verification_fault = Some(VerificationFault::WrongDigest);
    let (_, hooks) = hooks();
    let result = f.run(bundled(), hooks, &knock::Cancel::new());
    assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
    assert_eq!(fs::read(f.final_path()).unwrap(), b"old daemon");
    assert_eq!(f.starts(), 0);
    assert_eq!(f.uploads, 1);
    assert!(!f
        .commands
        .iter()
        .any(|(what, _)| what == "qshd publication"));
    let temporary = f.temporary.take().unwrap();
    let path = temporary.0.clone();
    assert!(Path::new(&path).exists());
    cleanup_temporary(&mut f, Some(temporary));
    assert!(!Path::new(&path).exists());
    assert_eq!(fs::read(f.final_path()).unwrap(), b"old daemon");
}
#[test]
fn verification_missing_hash_tool_is_typed_and_stops_before_upload() {
    let mut f = Fixture::new();
    f.verification_fault = Some(VerificationFault::MissingTool);
    let (_, hooks) = hooks();
    let result = f.run(bundled(), hooks, &knock::Cancel::new());
    let error = result.unwrap_err();
    assert!(matches!(error, BringUpError::Verify(_)));
    assert!(error.to_string().contains("hash utility unavailable"));
    assert_eq!(f.starts(), 0);
    assert_eq!(f.uploads, 0);
    assert!(!f.final_path().exists());
    assert!(f.temporary.is_none());
}
#[test]
fn verification_extra_stdout_refuses_publication_and_cleans_owned_upload() {
    let mut f = Fixture::new();
    f.verification_fault = Some(VerificationFault::ExtraRecord);
    let (_, hooks) = hooks();
    let result = f.run(bundled(), hooks, &knock::Cancel::new());
    assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
    assert_eq!(f.starts(), 0);
    assert_eq!(f.uploads, 1);
    assert!(!f.final_path().exists());
    assert!(!f
        .commands
        .iter()
        .any(|(what, _)| what == "qshd publication"));
    let temporary = f.temporary.take().unwrap();
    let path = temporary.0.clone();
    assert!(Path::new(&path).exists());
    cleanup_temporary(&mut f, Some(temporary));
    assert!(!Path::new(&path).exists());
    assert!(!f.final_path().exists());
}
#[test]
fn verification_stderr_warning_preserves_valid_stdout_and_publication() {
    let mut f = Fixture::new();
    f.verification_fault = Some(VerificationFault::Warning);
    let (_, hooks) = hooks();
    let result = f.run(bundled(), hooks, &knock::Cancel::new());
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(f.starts(), 1);
    assert_eq!(f.uploads, 1);
    assert_eq!(
        fs::read(f.final_path()).unwrap(),
        b"owned fixture; never execute"
    );
    assert!(f.temporary.is_none());
    assert!(fs::read_dir(f.final_path().parent().unwrap())
        .unwrap()
        .all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".qshd-")));
}
