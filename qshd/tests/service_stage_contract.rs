pub use qshd::state;
#[path = "../src/service_stage.rs"]
mod service_stage;

use daemon_bootstrap_protocol::CandidateImageIdentity;
use service_stage::{PreparedStage, StageRoot};
use sha2::{Digest, Sha256};
use std::fs::{self, File, Permissions};
use std::os::unix::fs::PermissionsExt;

fn check() -> state::SelfCheck {
    state::SelfCheck {
        build: 42,
        arch: "test-arch".into(),
        protocol: 1,
        protocols: vec![1],
        handover_versions: vec![],
        transport_features: vec![],
    }
}

#[test]
fn selected_open_file_is_copied_verified_and_removed_on_drop() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    let source = temp.path().join("selected");
    fs::write(&source, b"selected executable bytes").unwrap();
    fs::set_permissions(&source, Permissions::from_mode(0o500)).unwrap();
    let mut source = File::open(&source).unwrap();
    let candidate = CandidateImageIdentity {
        build: 42,
        checksum: hex::encode(Sha256::digest(b"selected executable bytes")),
    };
    let stage = PreparedStage::prepare(
        StageRoot::from_trusted(File::open(temp.path()).unwrap(), temp.path().into()).unwrap(),
        &mut source,
        candidate.clone(),
        "test-arch",
        1,
        b"opaque operation",
        |path| {
            assert_eq!(fs::read(path).unwrap(), b"selected executable bytes");
            Ok(check())
        },
    )
    .unwrap();
    stage.validate(&candidate, b"opaque operation").unwrap();
    assert_eq!(
        fs::metadata(stage.executable())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
    let path = stage.executable().to_owned();
    drop(stage);
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
}

// This fixture has an ordinary single-threaded main: reexec/adoption/fork never
// run from a libtest worker or after a Tokio runtime has created threads.
const HELPER: &str = r#"
pub use qshd::state;
#[path = "@MODULE@"] mod service_stage;
use service_stage::*;
use daemon_bootstrap_protocol::CandidateImageIdentity;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use sha2::{Sha256, Digest};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use nix::libc;
fn main() {
    let base = std::path::PathBuf::from(std::env::var_os("STAGE_TEST_ROOT").unwrap());
    let operation = b"helper-operation";
    let record = base.join("candidate.json");
    if let Some(encoded) = std::env::var_os(LAUNCH_ENV) {
        std::env::remove_var(LAUNCH_ENV);
        let candidate: CandidateImageIdentity = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        let mut adopted = AdoptedStage::adopt(StageLaunchContext::parse(encoded.to_str().unwrap()).unwrap(), &candidate, operation).unwrap();
        adopted.validate(&candidate, operation).unwrap();
        assert_eq!(adopted.operation(), operation);
        assert_eq!(std::env::args_os().nth(1).unwrap().as_bytes(), b"opaque-\xff");
        if std::env::var("STAGE_TEST_MODE").unwrap() == "fork" {
            let mut pipe = [0; 2]; assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
            let pid = unsafe { libc::fork() }; assert!(pid >= 0);
            if pid == 0 {
                unsafe { libc::close(pipe[1]); }
                let mut ready = 0u8; assert_eq!(unsafe { libc::read(pipe[0], (&mut ready as *mut u8).cast(), 1) }, 1);
                unsafe { libc::close(pipe[0]); }
                adopted.validate(&candidate, operation).unwrap();
                adopted.cleanup().unwrap();
                std::process::exit(0);
            }
            unsafe { libc::close(pipe[0]); }
            adopted.disarm_cleanup(); drop(adopted);
            let ready = 1u8; assert_eq!(unsafe { libc::write(pipe[1], (&ready as *const u8).cast(), 1) }, 1);
            unsafe { libc::close(pipe[1]); }
            let mut status = 0; assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status)); assert_eq!(libc::WEXITSTATUS(status), 0);
        } else { adopted.cleanup().unwrap(); }
        return;
    }
    let root = base.join("stages"); fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let source_path = std::env::current_exe().unwrap();
    let bytes = fs::read(&source_path).unwrap();
    let candidate = CandidateImageIdentity { build: 42, checksum: hex::encode(Sha256::digest(&bytes)) };
    fs::write(&record, serde_json::to_vec(&candidate).unwrap()).unwrap();
    let mut source = File::open(&source_path).unwrap();
    let stage = PreparedStage::prepare(StageRoot::from_trusted(File::open(&root).unwrap(), root).unwrap(),
        &mut source, candidate, "fixture", 1, operation, |_| Ok(state::SelfCheck {
            build:42, arch:"fixture".into(), protocol:1, protocols:vec![1], handover_versions:vec![], transport_features:vec![] })).unwrap();
    fs::write(base.join("stage-path"), stage.executable().as_os_str().as_encoded_bytes()).unwrap();
    if std::env::var("STAGE_TEST_MODE").unwrap() == "reject-env" {
        std::env::set_var(LAUNCH_ENV, "forged");
        assert!(matches!(stage.reexec(&[]), Err(StageError::Invalid)));
        assert_eq!(std::env::var(LAUNCH_ENV).unwrap(), "forged");
        return;
    }
    stage.reexec(&[std::ffi::OsString::from_vec(b"opaque-\xff".to_vec())]).unwrap();
}
"#;

#[test]
fn single_threaded_helper_reexec_adopts_and_transfers_cleanup_across_fork() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("helper.rs");
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service_stage.rs");
    fs::write(
        &source,
        HELPER
            .lines()
            .map(|line| line.strip_prefix('+').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("@MODULE@", module.to_str().unwrap()),
    )
    .unwrap();
    let executable = temp.path().join("helper");
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let mut compiler = Command::new("rustc");
    compiler
        .arg("--edition=2021")
        .arg("--crate-name=stage_owned_helper")
        .arg("-Cstrip=symbols")
        .arg("-Adead_code")
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    // Resolve this test's exact Cargo fingerprints, including versions when
    // multiple dependency generations coexist in the exclusive cache.
    let test_binary = std::env::current_exe().unwrap();
    let test_hash = test_binary
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("service_stage_contract-")
        .unwrap();
    let fingerprints = deps.parent().unwrap().join(".fingerprint");
    let test_metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(fingerprints.join(format!(
            "qshd-{test_hash}/test-integration-test-service_stage_contract.json"
        )))
        .unwrap(),
    )
    .unwrap();
    for name in [
        "qshd",
        "daemon_bootstrap_protocol",
        "base64",
        "rand_core",
        "serde",
        "serde_json",
        "sha2",
        "hex",
        "nix",
    ] {
        let dependency = test_metadata["deps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|dep| dep[1] == name)
            .unwrap();
        let expected = hex::encode(dependency[3].as_u64().unwrap().to_le_bytes());
        let matched = fs::read_dir(&fingerprints)
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| {
                fs::read_to_string(entry.path().join(format!("lib-{name}")))
                    .is_ok_and(|text| text == expected)
            })
            .unwrap();
        let artifact_name = matched.file_name();
        let artifact_hash = artifact_name.to_str().unwrap().rsplit_once('-').unwrap().1;
        let library = deps.join(format!("lib{name}-{artifact_hash}.rlib"));
        compiler
            .arg("--extern")
            .arg(format!("{name}={}", library.display()));
    }
    let output = compiler.output().unwrap();
    assert!(
        output.status.success(),
        "helper compilation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::set_permissions(&executable, Permissions::from_mode(0o500)).unwrap();
    for mode in ["adopt", "fork", "reject-env"] {
        let base = temp.path().join(mode);
        fs::create_dir(&base).unwrap();
        let output = Command::new(&executable)
            .env("STAGE_TEST_ROOT", &base)
            .env("STAGE_TEST_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "helper {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = std::path::PathBuf::from(
            String::from_utf8(fs::read(base.join("stage-path")).unwrap()).unwrap(),
        );
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
        assert_eq!(fs::read_dir(base.join("stages")).unwrap().count(), 0);
    }
}

#[test]
fn actual_selected_qshd_self_check_runs_from_closed_writable_stage() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
    let selected = temp.path().join("selected-qshd");
    fs::copy(env!("CARGO_BIN_EXE_qshd"), &selected).unwrap();
    // Only this private test copy is stripped, before computing its identity.
    assert!(Command::new("strip")
        .arg(&selected)
        .status()
        .unwrap()
        .success());
    #[cfg(target_os = "macos")]
    assert!(Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--identifier",
            "org.qsh.fixture.service527.stage"
        ])
        .arg(&selected)
        .status()
        .unwrap()
        .success());
    fs::set_permissions(&selected, Permissions::from_mode(0o500)).unwrap();
    let output = Command::new(&selected).arg("self-check").output().unwrap();
    assert!(output.status.success());
    let expected =
        state::SelfCheck::from_line(std::str::from_utf8(&output.stdout).unwrap()).unwrap();
    let candidate = CandidateImageIdentity {
        build: expected.build,
        checksum: hex::encode(Sha256::digest(fs::read(&selected).unwrap())),
    };
    let mut source = File::open(&selected).unwrap();
    let stage = PreparedStage::prepare(
        StageRoot::from_trusted(File::open(temp.path()).unwrap(), temp.path().into()).unwrap(),
        &mut source,
        candidate.clone(),
        &expected.arch,
        expected.protocol,
        b"real self-check",
        |path| {
            let output = Command::new(path)
                .arg("self-check")
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err("self-check failed".into());
            }
            state::SelfCheck::from_line(
                std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        },
    )
    .unwrap();
    stage.validate(&candidate, b"real self-check").unwrap();
}
