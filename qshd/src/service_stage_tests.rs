use super::*;
use std::fs;
use std::os::unix::fs::symlink;

fn check() -> SelfCheck {
    SelfCheck {
        build: 42,
        arch: "fixture".into(),
        protocol: 1,
        protocols: vec![1],
        handover_versions: vec![],
        transport_features: vec![],
    }
}
struct Fixture {
    temp: tempfile::TempDir,
    source: File,
    candidate: CandidateImageIdentity,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("source");
        fs::write(&path, b"selected image").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        Self {
            source: File::open(&path).unwrap(),
            temp,
            candidate: CandidateImageIdentity {
                build: 42,
                checksum: hex::encode(Sha256::digest(b"selected image")),
            },
        }
    }
    fn root(&self) -> StageRoot {
        StageRoot::from_trusted(
            File::open(self.temp.path()).unwrap(),
            self.temp.path().into(),
        )
        .unwrap()
    }
    fn prepare(&mut self) -> PreparedStage {
        PreparedStage::prepare(
            self.root(),
            &mut self.source,
            self.candidate.clone(),
            "fixture",
            1,
            b"operation",
            |_| Ok(check()),
        )
        .unwrap()
    }
    fn stages(&self) -> usize {
        fs::read_dir(self.temp.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .as_bytes()
                    .starts_with(b"stage-")
            })
            .count()
    }
}
fn context(stage: &PreparedStage) -> (String, Vec<File>) {
    let custody = &stage.custody;
    let handles = vec![
        duplicate(&custody.root.directory).unwrap(),
        duplicate(&custody.directory).unwrap(),
        duplicate(custody.executable.as_ref().unwrap()).unwrap(),
    ];
    let context = StageLaunchContext {
        version: 1,
        nonce: custody.stage_name[6..].into(),
        stage_name: custody.stage_name.clone(),
        root_route: custody.root.route.clone(),
        root: custody.root.identity.clone(),
        directory: custody.stage_identity.clone(),
        executable: custody.image_identity.clone().unwrap(),
        descriptors: [
            handles[0].as_raw_fd(),
            handles[1].as_raw_fd(),
            handles[2].as_raw_fd(),
        ],
        candidate: stage.candidate.clone(),
        operation: STANDARD.encode(&stage.operation),
        operation_digest: hex::encode(Sha256::digest(&stage.operation)),
    };
    (serde_json::to_string(&context).unwrap(), handles)
}
fn parsed(encoded: &str) -> StageLaunchContext {
    StageLaunchContext::parse(encoded).unwrap()
}

#[test]
fn wrong_digest_does_not_reach_self_check_or_leave_stage() {
    let mut f = Fixture::new();
    let mut candidate = f.candidate.clone();
    candidate.checksum = "00".repeat(32);
    let result = PreparedStage::prepare(
        f.root(),
        &mut f.source,
        candidate,
        "fixture",
        1,
        b"operation",
        |_| panic!("digest mismatch must prevent execution"),
    );
    assert!(matches!(result, Err(StageError::Changed)));
    assert_eq!(f.stages(), 0);
}
#[test]
fn self_check_rejects_wrong_build_arch_protocol_and_failed_execution() {
    for field in 0..4 {
        let mut f = Fixture::new();
        let result = PreparedStage::prepare(
            f.root(),
            &mut f.source,
            f.candidate.clone(),
            "fixture",
            1,
            b"operation",
            |_| {
                let mut value = check();
                match field {
                    0 => value.build = 43,
                    1 => value.arch = "other".into(),
                    2 => value.protocols = vec![2],
                    _ => return Err("fixture failure".into()),
                }
                Ok(value)
            },
        );
        assert!(matches!(result, Err(StageError::CheckFailed)));
        assert_eq!(f.stages(), 0);
    }
}
#[test]
fn self_check_can_report_new_preference_while_accepting_required_protocol() {
    let mut f = Fixture::new();
    let stage = PreparedStage::prepare(
        f.root(),
        &mut f.source,
        f.candidate.clone(),
        "fixture",
        1,
        b"operation",
        |_| {
            let mut value = check();
            value.protocol = 2;
            value.protocols = vec![1, 2];
            Ok(value)
        },
    )
    .unwrap();
    stage.validate(&f.candidate, b"operation").unwrap();
}
#[test]
fn empty_oversized_and_unsafe_source_are_rejected() {
    for case in 0..5 {
        let mut f = Fixture::new();
        let path = f.temp.path().join("source");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        match case {
            0 => File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(0)
                .unwrap(),
            1 => File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(MAX_STAGE_IMAGE + 1)
                .unwrap(),
            2 => fs::set_permissions(&path, fs::Permissions::from_mode(0o722)).unwrap(),
            3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap(),
            _ => fs::hard_link(&path, f.temp.path().join("hardlink")).unwrap(),
        }
        let result = PreparedStage::prepare(
            f.root(),
            &mut f.source,
            f.candidate.clone(),
            "fixture",
            1,
            b"operation",
            |_| panic!("source rejected before execution"),
        );
        assert!(result.is_err(), "case {case}");
        assert_eq!(f.stages(), 0);
    }
}
#[test]
fn operation_and_candidate_are_bounded_before_stage_creation() {
    let mut f = Fixture::new();
    let mut candidate = f.candidate.clone();
    candidate.checksum = "invalid".into();
    assert!(matches!(
        PreparedStage::prepare(
            f.root(),
            &mut f.source,
            candidate,
            "fixture",
            1,
            b"operation",
            |_| Ok(check())
        ),
        Err(StageError::Invalid)
    ));
    assert!(matches!(
        PreparedStage::prepare(
            f.root(),
            &mut f.source,
            f.candidate.clone(),
            "fixture",
            1,
            &vec![0; MAX_OPERATION_CONTEXT + 1],
            |_| Ok(check())
        ),
        Err(StageError::TooLarge)
    ));
    assert_eq!(f.stages(), 0);
}
#[test]
fn private_root_rejects_symlink_non_directory_mode_and_route_replacement() {
    let f = Fixture::new();
    assert!(
        StageRoot::from_trusted(f.source.try_clone().unwrap(), f.temp.path().join("source"))
            .is_err()
    );
    let alias = f.temp.path().join("alias");
    symlink(f.temp.path(), &alias).unwrap();
    assert!(StageRoot::from_trusted(File::open(f.temp.path()).unwrap(), alias).is_err());
    fs::set_permissions(f.temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        StageRoot::from_trusted(File::open(f.temp.path()).unwrap(), f.temp.path().into()).is_err()
    );
    fs::set_permissions(f.temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let nested = f.temp.path().join("root");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    let root = StageRoot::from_trusted(File::open(&nested).unwrap(), nested.clone()).unwrap();
    fs::rename(&nested, f.temp.path().join("retained")).unwrap();
    fs::create_dir(&nested).unwrap();
    assert!(root.revalidate().is_err());
}
#[test]
fn staged_tamper_and_operation_mismatch_are_detected() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    assert!(stage.validate(&f.candidate, b"other").is_err());
    let mut other = f.candidate.clone();
    other.build += 1;
    assert!(stage.validate(&other, b"operation").is_err());
    fs::set_permissions(stage.executable(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stage.executable(), b"changed image!").unwrap();
    fs::set_permissions(stage.executable(), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(stage.validate(&f.candidate, b"operation").is_err());
}
#[test]
fn self_check_tampering_is_detected_after_callback() {
    let mut f = Fixture::new();
    let result = PreparedStage::prepare(
        f.root(),
        &mut f.source,
        f.candidate.clone(),
        "fixture",
        1,
        b"operation",
        |path| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(path, b"changed image!").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
            Ok(check())
        },
    );
    assert!(matches!(result, Err(StageError::Changed)));
    assert_eq!(f.stages(), 0);
}
#[test]
fn replaced_source_path_does_not_change_selected_stage_bytes() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let source_path = f.temp.path().join("source");
    fs::remove_file(&source_path).unwrap();
    fs::write(&source_path, b"replacement source").unwrap();
    stage.validate(&f.candidate, b"operation").unwrap();
    assert_eq!(fs::read(stage.executable()).unwrap(), b"selected image");
}
#[test]
fn cleanup_preserves_replacement_leaf_and_foreign_extra_file() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let path = stage.executable().to_owned();
    fs::rename(&path, path.with_file_name("retained")).unwrap();
    fs::write(&path, b"foreign").unwrap();
    drop(stage);
    assert_eq!(fs::read(&path).unwrap(), b"foreign");
    assert!(path.with_file_name("retained").exists());
    let mut f = Fixture::new();
    let stage = f.prepare();
    let path = stage.executable().to_owned();
    fs::write(path.with_file_name("foreign"), b"extra").unwrap();
    drop(stage);
    assert!(!path.exists());
    assert_eq!(fs::read(path.with_file_name("foreign")).unwrap(), b"extra");
}
#[test]
fn cleanup_preserves_replaced_stage_directory() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let parent = stage.executable().parent().unwrap().to_owned();
    fs::rename(&parent, f.temp.path().join("retained-stage")).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::write(parent.join("qshd"), b"foreign").unwrap();
    drop(stage);
    assert_eq!(fs::read(parent.join("qshd")).unwrap(), b"foreign");
    assert!(f.temp.path().join("retained-stage/qshd").exists());
}
#[test]
fn parse_rejects_unknown_duplicate_fields_and_invalid_bounded_metadata() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let (encoded, _handles) = context(&stage);
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("nonce", serde_json::json!("00")),
        ("stage_name", serde_json::json!("../outside")),
        ("root_route", serde_json::json!("relative")),
        ("descriptors", serde_json::json!([0, 5, 6])),
        ("descriptors", serde_json::json!([5, 5, 6])),
        ("descriptors", serde_json::json!([-1, 5, 6])),
        ("operation", serde_json::json!("??")),
        ("operation_digest", serde_json::json!("00".repeat(32))),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        json[field] = value;
        assert!(
            StageLaunchContext::parse(&json.to_string()).is_err(),
            "field {field}"
        );
    }
    assert!(StageLaunchContext::parse(&format!("{{\"version\":1,{}", &encoded[1..])).is_err());
    assert!(StageLaunchContext::parse(&" ".repeat(MAX_LAUNCH_CONTEXT + 1)).is_err());
}
#[test]
fn failed_adoption_never_consumes_unrelated_or_mismatched_descriptors() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let (encoded, handles) = context(&stage);
    assert!(AdoptedStage::adopt(parsed(&encoded), &f.candidate, b"wrong operation").is_err());
    let mut wrong = f.candidate.clone();
    wrong.build += 1;
    assert!(AdoptedStage::adopt(parsed(&encoded), &wrong, b"operation").is_err());
    let mut json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    json["descriptors"][2] = serde_json::json!(f.source.as_raw_fd());
    assert!(AdoptedStage::adopt(parsed(&json.to_string()), &f.candidate, b"operation").is_err());
    for file in handles {
        assert!(file.metadata().is_ok());
    }
    assert!(f.source.metadata().is_ok());
    assert!(unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0);
}
#[test]
fn adopted_custody_closes_validated_inherited_descriptors_and_cleans_explicitly() {
    let mut f = Fixture::new();
    let mut stage = f.prepare();
    let path = stage.executable().to_owned();
    let (encoded, handles) = context(&stage);
    // Ownership of exactly these validated duplicates passes to adoption.
    use std::os::fd::IntoRawFd;
    let inherited: Vec<_> = handles.into_iter().map(IntoRawFd::into_raw_fd).collect();
    let adopted = AdoptedStage::adopt(parsed(&encoded), &f.candidate, b"operation").unwrap();
    stage.custody.cleanup = false;
    drop(stage);
    for fd in inherited {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    }
    assert_eq!(adopted.operation(), b"operation");
    adopted.validate(&f.candidate, b"operation").unwrap();
    for file in [
        &adopted.custody.root.directory,
        &adopted.custody.directory,
        adopted.custody.executable.as_ref().unwrap(),
    ] {
        assert_ne!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    adopted.cleanup().unwrap();
    assert!(!path.parent().unwrap().exists());
}
#[test]
fn maximum_operation_round_trips_inside_bounded_launch_context() {
    let mut f = Fixture::new();
    let operation = vec![0xff; MAX_OPERATION_CONTEXT];
    let stage = PreparedStage::prepare(
        f.root(),
        &mut f.source,
        f.candidate.clone(),
        "fixture",
        1,
        &operation,
        |_| Ok(check()),
    )
    .unwrap();
    let (encoded, _handles) = context(&stage);
    assert!(encoded.len() <= MAX_LAUNCH_CONTEXT);
    assert_eq!(parsed(&encoded).operation_bytes().unwrap(), operation);
}
#[test]
fn failed_exec_cleans_stage_without_changing_internal_environment() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let path = stage.executable().to_owned();
    assert!(stage.reexec(&[]).is_err());
    assert!(!path.parent().unwrap().exists());
    assert!(std::env::var_os(LAUNCH_ENV).is_none());
}
#[test]
fn caller_cannot_inject_launch_context_through_arguments() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let path = stage.executable().to_owned();
    assert!(matches!(
        stage.reexec(&[OsString::from(format!("{LAUNCH_ENV}=forged"))]),
        Err(StageError::Invalid)
    ));
    assert!(!path.exists());
}

#[test]
fn disarm_transfers_cleanup_without_removing_child_custody() {
    use std::os::fd::IntoRawFd;
    let mut f = Fixture::new();
    let mut stage = f.prepare();
    let (encoded, handles) = context(&stage);
    for file in handles {
        let _ = file.into_raw_fd();
    }
    let mut adopted = AdoptedStage::adopt(parsed(&encoded), &f.candidate, b"operation").unwrap();
    stage.custody.cleanup = false;
    let path = stage.executable().to_owned();
    adopted.disarm_cleanup();
    drop(adopted);
    assert!(path.exists());
    stage.validate(&f.candidate, b"operation").unwrap();
    stage.custody.cleanup = true;
    drop(stage);
    assert!(!path.exists());
}

#[test]
fn streamed_hash_enforces_cap_without_relying_on_initial_file_size_check() {
    let temp = tempfile::tempfile().unwrap();
    temp.set_len(MAX_STAGE_IMAGE + 1).unwrap();
    let mut consumed = 0;
    let result = image_digest(&temp, |bytes| {
        consumed += bytes.len();
        Ok(())
    });
    assert!(matches!(result, Err(StageError::TooLarge)));
    assert_eq!(consumed, 64 * 1024 * 1024);
}

#[test]
fn selected_source_adapter_refuses_symlink_and_stage_rejects_directory() {
    let mut f = Fixture::new();
    let alias = f.temp.path().join("source-link");
    symlink(f.temp.path().join("source"), &alias).unwrap();
    assert!(open_path(&alias, libc::O_RDONLY).is_err());
    f.source = File::open(f.temp.path()).unwrap();
    assert!(PreparedStage::prepare(
        f.root(),
        &mut f.source,
        f.candidate.clone(),
        "fixture",
        1,
        b"operation",
        |_| panic!("directory is not executable image")
    )
    .is_err());
}

#[test]
fn substituted_fifo_is_rejected_without_blocking_validation() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let path = stage.executable().to_owned();
    fs::remove_file(&path).unwrap();
    let fifo = cstring(path.as_os_str()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let candidate = f.candidate.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let validator = std::thread::spawn(move || {
        sender
            .send(stage.validate(&candidate, b"operation").is_err())
            .unwrap();
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(1));
    // Release an old blocking open so a failed assertion still joins its worker.
    let writer = open_path(&path, libc::O_WRONLY | libc::O_NONBLOCK).ok();
    validator.join().unwrap();
    drop(writer);
    assert!(
        result.is_ok_and(|rejected| rejected),
        "validation blocked on substituted FIFO"
    );
    assert!(path.exists());
}

#[test]
fn adoption_rechecks_context_even_when_deserialized_without_parse() {
    let mut f = Fixture::new();
    let stage = f.prepare();
    let (encoded, handles) = context(&stage);
    let mut json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    json["version"] = serde_json::json!(2);
    let bypassed: StageLaunchContext = serde_json::from_value(json).unwrap();
    // Hold descriptor ownership in this scope. A bug that succeeds would close
    // them, so disarm the Files first and reclaim only on the rejection path.
    use std::os::fd::IntoRawFd;
    let raw: Vec<_> = handles.into_iter().map(IntoRawFd::into_raw_fd).collect();
    let result = AdoptedStage::adopt(bypassed, &f.candidate, b"operation");
    if result.is_err() {
        for fd in raw {
            drop(unsafe { File::from_raw_fd(fd) });
        }
    }
    assert!(
        result.is_err(),
        "adoption accepted an unchecked context version"
    );
}
