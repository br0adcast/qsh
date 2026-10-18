mod support_home;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{atomic::Ordering, Arc, Condvar, Mutex};

use bringup::*;
use sha2::{Digest, Sha256};
use support_home::*;

const VERSION: &str = "0.4.0";
const SCRIPT: &[u8] = b"#!/bin/sh\nprintf x >> \"$HOME/ensure-ran\"\nprintf '%s\\n' 'server-pubkey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=' 'TRANSPORT-READY {\"version\":\"0.4.0\",\"ports\":[60022]}'\n";

fn source(bytes: &[u8]) -> Arc<MemoryImages> {
    Arc::new(MemoryImages {
        image: DaemonImage {
            request: ImageRequest::new(
                Platform::from_uname("Linux", std::env::consts::ARCH).unwrap(),
                VERSION,
            )
            .unwrap(),
            size: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            bytes: Arc::from(bytes),
        },
        calls: 0.into(),
    })
}

fn approval(accept: bool) -> Arc<RecordingApproval> {
    Arc::new(RecordingApproval {
        accept,
        offers: Mutex::new(vec![]),
    })
}

fn hooks(
    source: Arc<MemoryImages>,
    approval: Arc<RecordingApproval>,
    observer: Arc<RecordingObserver>,
) -> BringUpHooks {
    BringUpHooks {
        source: Some(source),
        approval,
        observer,
        timing: InstallTiming::default(),
    }
}

fn bundled() -> InstallPolicy {
    InstallPolicy::EnsureBundled {
        version: VERSION.into(),
    }
}
fn ask() -> InstallPolicy {
    InstallPolicy::AskIfMissing {
        version: VERSION.into(),
    }
}
fn final_path(sb: &Sandbox) -> std::path::PathBuf {
    sb.cache()
        .join(format!("qshd-0.4.0-{}", std::env::consts::ARCH))
}
fn run(
    sb: &mut Sandbox,
    policy: InstallPolicy,
    hooks: BringUpHooks,
    cancel: &knock::Cancel,
) -> Result<Ready, BringUpError> {
    bring_up_with(
        sb.request(60022),
        policy,
        hooks,
        Arc::new(knock::NoBind),
        cancel,
    )
}
fn assert_not_started(sb: &Sandbox) {
    assert!(!sb.home.path().join("ensure-ran").exists());
}
fn assert_no_temporary(sb: &Sandbox) {
    for entry in fs::read_dir(sb.cache()).unwrap() {
        assert!(!entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".qshd-"));
    }
}

#[test]
fn real_ssh_stages_precede_lookup_with_and_without_knocking() {
    for knocking in [true, false] {
        let mut sb = Sandbox::start();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut request = sb.request(60022);
        if knocking {
            request.ssh.knock.push(knock::KnockStep {
                protocol: knock::KnockProtocol::Tcp,
                port: listener.local_addr().unwrap().port(),
                payload: b"bringup-knock".to_vec(),
                delay_after_ms: 0,
            });
        }
        let observer = Arc::new(RecordingObserver::default());
        let result = bring_up_with(
            request,
            InstallPolicy::ExistingOnly,
            hooks(source(SCRIPT), approval(false), observer.clone()),
            Arc::new(knock::NoBind),
            &knock::Cancel::new(),
        );
        assert!(
            matches!(result, Err(BringUpError::InstallRequired)),
            "{result:?}"
        );
        if knocking {
            listener.accept().unwrap();
        }
        let stages: Vec<_> = observer
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|event| (event.stage, event.finished))
            .collect();
        let mut expected = vec![];
        if knocking {
            expected.push((BringUpStage::Knocking, false));
        }
        expected.extend([
            (BringUpStage::Connecting, false),
            (BringUpStage::Connecting, true),
            (BringUpStage::Locating, false),
            (BringUpStage::Locating, true),
        ]);
        assert_eq!(stages, expected, "knocking={knocking}");
    }
}

#[test]
fn missing_daemon_is_installed_after_approval() {
    let mut sb = Sandbox::start();
    let source = source(SCRIPT);
    let approval = approval(true);
    let observer = Arc::new(RecordingObserver::default());
    let ready = run(
        &mut sb,
        ask(),
        hooks(source.clone(), approval.clone(), observer.clone()),
        &knock::Cancel::new(),
    )
    .unwrap();
    assert_eq!(ready.ports, [60022]);
    assert_eq!(ready.server_pubkey, [7; 32]);
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        approval.offers.lock().unwrap()[0].remote_path,
        final_path(&sb).to_str().unwrap()
    );
    assert_eq!(fs::read(final_path(&sb)).unwrap(), SCRIPT);
    assert_eq!(
        fs::metadata(final_path(&sb)).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::read(sb.home.path().join("ensure-ran")).unwrap(), b"x");
    assert!(observer
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.stage == BringUpStage::Uploading && e.finished));
    assert_no_temporary(&sb);
}

#[test]
fn existing_daemon_does_not_request_an_image() {
    for policy in [InstallPolicy::ExistingOnly, ask()] {
        let mut sb = Sandbox::start();
        fs::write(final_path(&sb), SCRIPT).unwrap();
        fs::set_permissions(final_path(&sb), fs::Permissions::from_mode(0o700)).unwrap();
        let source = source(b"unused");
        let approval = approval(true);
        run(
            &mut sb,
            policy,
            hooks(source.clone(), approval.clone(), Arc::default()),
            &knock::Cancel::new(),
        )
        .unwrap();
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        assert!(approval.offers.lock().unwrap().is_empty());
    }
}

#[test]
fn refusal_never_loads_or_starts() {
    let mut sb = Sandbox::start();
    let source = source(SCRIPT);
    let result = run(
        &mut sb,
        ask(),
        hooks(source.clone(), approval(false), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(matches!(result, Err(BringUpError::Declined)), "{result:?}");
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_not_started(&sb);
    assert!(!final_path(&sb).exists());
}

#[test]
fn bad_remote_sum_keeps_old_file() {
    let mut sb = Sandbox::start();
    let original = b"old daemon";
    fs::write(final_path(&sb), original).unwrap();
    sb.fake_qshd(
        &sb.home.path().join("bin/sha256sum"),
        "printf '%064d  file\\n' 0",
    );
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
    assert_eq!(fs::read(final_path(&sb)).unwrap(), original);
    assert_not_started(&sb);
    assert_no_temporary(&sb);
}

fn cancel_at(stage: BringUpStage, finished: bool, published: bool) {
    let mut sb = Sandbox::start();
    let cancel = knock::Cancel::new();
    let token = cancel.clone();
    let observer = Arc::new(RecordingObserver {
        callback: Some(Box::new(move |e| {
            if e.stage == stage && e.finished == finished {
                token.cancel();
            }
        })),
        ..Default::default()
    });
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), observer),
        &cancel,
    );
    assert!(
        matches!(result, Err(BringUpError::Ssh(ssh::SshError::Cancelled))),
        "{result:?}"
    );
    assert_not_started(&sb);
    assert_eq!(final_path(&sb).exists(), published);
    if published {
        assert_eq!(fs::read(final_path(&sb)).unwrap(), SCRIPT);
    }
    assert_no_temporary(&sb);
}

#[test]
fn cancel_before_publish_does_not_start() {
    cancel_at(BringUpStage::Publishing, false, false);
}
#[test]
fn cancel_after_publish_does_not_start() {
    cancel_at(BringUpStage::Publishing, true, true);
}
#[test]
fn cancel_immediately_before_ensure_does_not_start() {
    cancel_at(BringUpStage::Starting, false, true);
}

#[test]
fn two_installs_never_publish_partial_bytes() {
    let mut sb = Sandbox::start();
    let a = SCRIPT.to_vec();
    let mut b = a.clone();
    b.extend_from_slice(b"# distinct image\n");
    let barrier = Arc::new((Mutex::new(0), Condvar::new()));
    let mut workers = vec![];
    for bytes in [a.clone(), b.clone()] {
        let barrier = barrier.clone();
        let req = sb.request(60022);
        let observer = Arc::new(RecordingObserver {
            callback: Some(Box::new(move |e| {
                if e.stage == BringUpStage::Publishing && !e.finished {
                    let (count, ready) = &*barrier;
                    let mut count = count.lock().unwrap();
                    *count += 1;
                    ready.notify_all();
                    let (count, _) = ready
                        .wait_timeout_while(count, std::time::Duration::from_secs(5), |count| {
                            *count < 2
                        })
                        .unwrap();
                    assert_eq!(*count, 2, "both installs must reach publication");
                }
            })),
            ..Default::default()
        });
        workers.push(std::thread::spawn(move || {
            bring_up_with(
                req,
                bundled(),
                hooks(source(&bytes), approval(true), observer),
                Arc::new(knock::NoBind),
                &knock::Cancel::new(),
            )
        }));
    }
    while workers.iter().any(|worker| !worker.is_finished()) {
        if let Ok(published) = fs::read(final_path(&sb)) {
            assert!(published == a || published == b);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
    let published = fs::read(final_path(&sb)).unwrap();
    assert!(published == a || published == b);
    assert_no_temporary(&sb);
}

#[test]
fn a_service_is_not_replaced() {
    let mut sb = Sandbox::start();
    fs::write(final_path(&sb), b"original").unwrap();
    sb.fake_qshd(&sb.home.path().join("bin/systemctl"), "exit 0");
    let source = source(SCRIPT);
    let result = run(
        &mut sb,
        bundled(),
        hooks(source.clone(), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::ServiceRunning(_))),
        "{result:?}"
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(final_path(&sb)).unwrap(), b"original");
    assert_not_started(&sb);
}

#[test]
fn source_must_match_platform_version_size_and_hash_before_writes() {
    for change in 0..5 {
        let mut sb = Sandbox::start();
        let mut source = source(SCRIPT);
        let image = &mut Arc::get_mut(&mut source).unwrap().image;
        match change {
            0 => image.request.platform.os = ServerOs::Darwin,
            1 => image.request.version = "0.5.0".into(),
            2 => image.size += 1,
            3 => image.sha256[0] ^= 1,
            _ => image.size = 33 * 1024 * 1024,
        }
        let result = run(
            &mut sb,
            bundled(),
            hooks(source, approval(true), Arc::default()),
            &knock::Cancel::new(),
        );
        assert!(matches!(result, Err(BringUpError::Image(_))), "{result:?}");
        assert_not_started(&sb);
        assert!(fs::read_dir(sb.cache()).unwrap().next().is_none());
    }
}

#[test]
fn matching_remote_image_skips_upload_but_sets_executable_mode() {
    let mut sb = Sandbox::start();
    fs::write(final_path(&sb), SCRIPT).unwrap();
    let observer = Arc::new(RecordingObserver::default());
    run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), observer.clone()),
        &knock::Cancel::new(),
    )
    .unwrap();
    assert!(!observer
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.stage == BringUpStage::Uploading));
    assert_eq!(
        fs::metadata(final_path(&sb)).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn absent_hash_utility_is_a_typed_failure() {
    let mut sb = Sandbox::start();
    sb.fake_qshd(
        &sb.home.path().join("bin/sha256sum"),
        "echo unavailable >&2; exit 127",
    );
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(matches!(result, Err(BringUpError::Verify(_))), "{result:?}");
    assert_not_started(&sb);
    assert!(!final_path(&sb).exists());
}

#[test]
fn denied_directory_write_is_a_typed_failure() {
    let mut sb = Sandbox::start();
    fs::set_permissions(sb.cache(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    fs::set_permissions(sb.cache(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(result, Err(BringUpError::Transfer(_))),
        "{result:?}"
    );
    assert_not_started(&sb);
}

#[test]
fn invalid_ready_is_reported_after_whole_file_was_published() {
    let mut sb = Sandbox::start();
    let bytes = b"#!/bin/sh\necho 'TRANSPORT-READY {}'\n";
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(bytes), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::BadReady(_))),
        "{result:?}"
    );
    assert_eq!(fs::read(final_path(&sb)).unwrap(), bytes);
}

#[test]
fn invalid_version_is_rejected_before_ssh_or_image_loading() {
    let mut sb = Sandbox::start();
    let source = source(SCRIPT);
    let mut req = sb.request(60022);
    req.ssh.port = 1;
    let result = bring_up_with(
        req,
        InstallPolicy::EnsureBundled {
            version: "../0.4.0".into(),
        },
        hooks(source.clone(), approval(true), Arc::default()),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::InvalidRequest(_))),
        "{result:?}"
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn existing_only_missing_is_install_required_but_legacy_is_missing() {
    let mut sb = Sandbox::start();
    let result = run(
        &mut sb,
        InstallPolicy::ExistingOnly,
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::InstallRequired)),
        "{result:?}"
    );
    let result = bring_up(
        sb.request(60022),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::QshdMissing)),
        "{result:?}"
    );
}

#[test]
fn absent_image_source_is_a_configuration_error() {
    let mut sb = Sandbox::start();
    let mut hooks = hooks(source(SCRIPT), approval(true), Arc::default());
    hooks.source = None;
    let result = run(&mut sb, bundled(), hooks, &knock::Cancel::new());
    assert!(
        matches!(result, Err(BringUpError::InvalidRequest(_))),
        "{result:?}"
    );
}

#[test]
fn unavailable_sftp_is_a_typed_transfer_failure() {
    let mut sb = Sandbox::start();
    // The independent SFTP marker round trip has already established isolation.
    // Reload only this test's owned sshd with a deliberately absent subsystem.
    let config = sb.sshd.dir.path().join("sshd_config");
    let text = fs::read_to_string(&config).unwrap().replace(
        "Subsystem sftp internal-sftp",
        "Subsystem sftp /nonexistent-qsh-test-sftp",
    );
    fs::write(config, text).unwrap();
    let pid: i32 = fs::read_to_string(sb.sshd.dir.path().join("sshd.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert!(String::from_utf8_lossy(&cmdline).contains(sb.sshd.dir.path().to_str().unwrap()));
    // SAFETY: pid is the live sshd owned by this Sandbox, verified above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sb.sshd.log().matches("Server listening").count() < 2 {
        assert!(
            std::time::Instant::now() < until,
            "test sshd did not reload"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::Transfer(_))),
        "{result:?}"
    );
    assert_not_started(&sb);
    assert!(!final_path(&sb).exists());
}

#[test]
fn unsupported_platform_never_asks_or_loads() {
    let mut sb = Sandbox::start();
    sb.fake_qshd(&sb.home.path().join("bin/uname"), "echo FreeBSD");
    let source = source(SCRIPT);
    let approval = approval(true);
    let result = run(
        &mut sb,
        ask(),
        hooks(source.clone(), approval.clone(), Arc::default()),
        &knock::Cancel::new(),
    );
    assert!(
        matches!(result, Err(BringUpError::UnsupportedPlatform(_))),
        "{result:?}"
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert!(approval.offers.lock().unwrap().is_empty());
    assert_not_started(&sb);
}

#[test]
fn failed_publication_keeps_old_file_and_cleans_only_own_temporary() {
    let mut sb = Sandbox::start();
    fs::write(final_path(&sb), b"old").unwrap();
    let foreign = sb.cache().join(".qshd-someone-else.tmp");
    fs::write(&foreign, b"foreign partial file").unwrap();
    sb.fake_qshd(
        &sb.home.path().join("bin/mv"),
        "printf '\\033[31mdenied\\033[0m' >&2; exit 19",
    );
    let result = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    );
    let Err(BringUpError::Publish(message)) = result else {
        panic!("{result:?}")
    };
    assert!(message.contains("19"));
    assert!(!message.contains('\x1b'));
    assert_eq!(fs::read(final_path(&sb)).unwrap(), b"old");
    assert_eq!(fs::read(&foreign).unwrap(), b"foreign partial file");
    assert_eq!(fs::read_dir(sb.cache()).unwrap().count(), 2);
    assert_not_started(&sb);
}

// Regression examples for bootstrap output and literal shell arguments.
#[test]
fn compatible_bootstrap_ready_examples_survive_the_full_install() {
    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let valid = format!("starting qshd...\nserver-pubkey: {KEY}\nsome diagnostic line\nTRANSPORT-READY {{\"version\":\"0.1.0\",\"ports\":[51820,51821],\"pid\":4242,\"warning\":\"\u{0434}\u{0435}\u{043c}\u{043e}\u{043d} \u{043e}\u{0442}\u{043b}\u{0438}\u{0447}\u{0430}\u{0435}\u{0442}\u{0441}\u{044f}\"}}\nbye\n");
    let mut sb = Sandbox::start();
    let bytes = format!("#!/bin/sh\ncat <<'READY'\n{valid}READY\n");
    let ready = run(
        &mut sb,
        bundled(),
        hooks(source(bytes.as_bytes()), approval(true), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap();
    assert_eq!(ready.version, "0.1.0");
    assert_eq!(ready.ports, [51820, 51821]);
    assert_eq!(ready.server_pubkey, std::array::from_fn(|i| i as u8));
    assert_eq!(ready.warning.as_deref(), Some("\u{0434}\u{0435}\u{043c}\u{043e}\u{043d} \u{043e}\u{0442}\u{043b}\u{0438}\u{0447}\u{0430}\u{0435}\u{0442}\u{0441}\u{044f}"));

    for output in [
        String::new(),
        "TRANSPORT-READY {\"version\":\"0.1.0\",\"ports\":[51820]}".into(),
        format!("server-pubkey: {KEY}\n"),
        format!("server-pubkey: {KEY}\nTRANSPORT-READY not-json\n"),
        "server-pubkey: not-base64!!!\nTRANSPORT-READY {\"version\":\"0.1.0\",\"ports\":[51820]}\n".into(),
        "server-pubkey: AAAAAAAAAAAAAAAAAAAAAA==\nTRANSPORT-READY {\"version\":\"0.1.0\",\"ports\":[51820]}\n".into(),
        "x".repeat(5000),
    ] {
        let mut sb = Sandbox::start();
        let bytes = format!("#!/bin/sh\ncat <<'READY'\n{output}\nREADY\n");
        let error = run(&mut sb, bundled(), hooks(source(bytes.as_bytes()), approval(true), Arc::default()), &knock::Cancel::new()).unwrap_err();
        assert!(matches!(&error, BringUpError::BadReady(_)), "{error:?}");
        assert!(error.to_string().chars().count() < 1200);
    }
}

#[test]
fn compatible_shell_control_examples_arrive_as_literal_ensure_arguments() {
    let hostile = [
        "",
        "plain",
        "with space",
        "it's",
        "''",
        "a;reboot",
        "$(touch pwned)",
        "`touch pwned`",
        "$HOME",
        "\"double\"",
        "back\\slash",
        "line\nnext",
        "tab\there",
        "glob*?[a]",
        "&& || | > < ~ # !",
        "-n",
        "s5-1; touch pwned $(id) `id` 'q'\nnext",
    ];
    for name in hostile {
        let mut sb = Sandbox::start();
        let mut bytes = b"#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$HOME/argv\"\n".to_vec();
        bytes.extend_from_slice(SCRIPT);
        let mut req = sb.request(60022);
        req.name = name.into();
        bring_up_with(
            req,
            bundled(),
            hooks(source(&bytes), approval(true), Arc::default()),
            Arc::new(knock::NoBind),
            &knock::Cancel::new(),
        )
        .unwrap();
        assert_eq!(fs::read(sb.home.path().join("argv")).unwrap(), format!("transport-ensure\0--name\0{name}\0--port\060022\0--client-pubkey\0CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\0").as_bytes());
        assert!(!sb.home.path().join("pwned").exists());
    }
}

#[test]
fn upload_progress_increases_and_finishes_at_the_image_size() {
    let mut sb = Sandbox::start();
    let mut bytes = SCRIPT.to_vec();
    bytes.extend_from_slice(format!("# {}\n", "x".repeat(300_000)).as_bytes());
    let observer = Arc::new(RecordingObserver::default());
    run(
        &mut sb,
        bundled(),
        hooks(source(&bytes), approval(true), observer.clone()),
        &knock::Cancel::new(),
    )
    .unwrap();
    let events = observer.events.lock().unwrap();
    let progress: Vec<_> = events
        .iter()
        .filter(|e| e.stage == BringUpStage::Uploading)
        .collect();
    assert!(!progress.is_empty());
    assert!(progress
        .windows(2)
        .all(|p| p[0].completed <= p[1].completed));
    let last = progress.last().unwrap();
    assert!(last.finished);
    assert_eq!(last.completed, bytes.len() as u64);
    assert_eq!(last.total, Some(bytes.len() as u64));
}

#[test]
fn compatible_exec_stderr_examples_keep_diagnostics_and_parse_stdout() {
    let mut sb = Sandbox::start();
    let mut bytes = b"#!/bin/sh\nprintf 'qshd banner\\n' >&2\n".to_vec();
    bytes.extend_from_slice(SCRIPT);
    let ready = run(
        &mut sb,
        bundled(),
        hooks(source(&bytes), approval(true), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap();
    assert_eq!(ready.ports, [60022]);

    let mut sb = Sandbox::start();
    let bytes = b"#!/bin/sh\nprintf 'bind: Address already in use\\n' >&2\nexit 1\n";
    let error = run(
        &mut sb,
        bundled(),
        hooks(source(bytes), approval(true), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap_err();
    assert!(matches!(&error, BringUpError::EnsureFailed(_)), "{error:?}");
    assert!(error.to_string().contains("bind: Address already in use"));
}

#[test]
fn compatible_invalid_port_and_shell_version_are_rejected_before_connecting() {
    for (port, version) in [(0, VERSION), (60022, "0.2;reboot")] {
        let mut sb = Sandbox::start();
        let source = source(SCRIPT);
        let mut req = sb.request(port);
        req.ssh.port = 1;
        let error = bring_up_with(
            req,
            InstallPolicy::EnsureBundled {
                version: version.into(),
            },
            hooks(source.clone(), approval(true), Arc::default()),
            Arc::new(knock::NoBind),
            &knock::Cancel::new(),
        )
        .unwrap_err();
        assert!(
            matches!(error, BringUpError::InvalidRequest(_)),
            "{error:?}"
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        assert_not_started(&sb);
    }
}

#[test]
fn compatible_architecture_aliases_and_image_names_remain_compatible() {
    for (uname, canonical) in [
        ("x86_64", "x86_64"),
        ("aarch64", "aarch64"),
        ("arm64", "aarch64"),
    ] {
        let platform = Platform::from_uname("Linux", uname).unwrap();
        assert_eq!(
            platform.file_name("0.1.0"),
            format!("qshd-0.1.0-{canonical}")
        );
    }
    assert!(matches!(
        Platform::from_uname("Linux", "armv7l"),
        Err(BringUpError::UnsupportedPlatform(_))
    ));
}

#[test]
fn stderr_warnings_do_not_corrupt_discovery_verification_or_readiness() {
    let mut sb = Sandbox::start();
    sb.fake_qshd(
        &sb.home.path().join("bin/uname"),
        "echo harmless-uname-warning >&2; exec /usr/bin/uname \"$@\"",
    );
    sb.fake_qshd(
        &sb.home.path().join("bin/sha256sum"),
        "echo harmless-hash-warning >&2; exec /usr/bin/sha256sum \"$@\"",
    );
    let mut bytes = b"#!/bin/sh\necho harmless-ready-warning >&2\n".to_vec();
    bytes.extend_from_slice(SCRIPT);
    let images = source(&bytes);
    let consent = approval(true);
    let ready = run(
        &mut sb,
        ask(),
        hooks(images.clone(), consent.clone(), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap();
    assert_eq!(ready.ports, [60022]);
    assert_eq!(ready.server_pubkey, [7; 32]);
    assert_eq!(fs::read(final_path(&sb)).unwrap(), bytes);
    assert_eq!(images.calls.load(Ordering::SeqCst), 1);
    assert_eq!(consent.offers.lock().unwrap().len(), 1);
    assert_no_temporary(&sb);
    run(
        &mut sb,
        ask(),
        hooks(images.clone(), consent.clone(), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap();
    assert_eq!(images.calls.load(Ordering::SeqCst), 1);
    assert_eq!(consent.offers.lock().unwrap().len(), 1);
}

#[test]
fn stdout_warning_in_discovery_never_prompts_or_loads_an_image() {
    let mut sb = Sandbox::start();
    sb.fake_qshd(
        &sb.home.path().join("bin/uname"),
        "echo unexpected-stdout; exec /usr/bin/uname \"$@\"",
    );
    let images = source(SCRIPT);
    let consent = approval(true);
    let error = run(
        &mut sb,
        ask(),
        hooks(images.clone(), consent.clone(), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap_err();
    assert!(matches!(error, BringUpError::EnsureFailed(_)), "{error:?}");
    assert_eq!(images.calls.load(Ordering::SeqCst), 0);
    assert!(consent.offers.lock().unwrap().is_empty());
    assert_not_started(&sb);
}

#[test]
fn readiness_requires_complete_utf8_stdout_and_successful_exit() {
    for (prefix, suffix, bad_ready) in [
        ("exec 1>&2\n", "", true),
        ("echo denied >&2\n", "exit 17\n", false),
        ("", "printf '\\377'\n", true),
        ("", "head -c 65536 /dev/zero | tr '\\000' x\n", true),
    ] {
        let mut sb = Sandbox::start();
        let bytes = [b"#!/bin/sh\n", prefix.as_bytes(), SCRIPT, suffix.as_bytes()].concat();
        let error = run(
            &mut sb,
            bundled(),
            hooks(source(&bytes), approval(true), Arc::default()),
            &knock::Cancel::new(),
        )
        .unwrap_err();
        if bad_ready {
            assert!(matches!(error, BringUpError::BadReady(_)), "{error:?}");
        } else {
            assert!(matches!(error, BringUpError::EnsureFailed(_)), "{error:?}");
            assert!(error.to_string().contains("denied"));
            assert!(error.to_string().contains("17"));
        }
        assert_no_temporary(&sb);
    }
}

#[test]
fn stderr_only_lookup_failure_preserves_its_reason() {
    let mut sb = Sandbox::start();
    sb.fake_qshd(
        &sb.home.path().join("bin/uname"),
        "echo lookup-denied >&2; exit 19",
    );
    let images = source(SCRIPT);
    let consent = approval(true);
    let error = run(
        &mut sb,
        ask(),
        hooks(images.clone(), consent.clone(), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap_err();
    assert!(matches!(error, BringUpError::EnsureFailed(_)), "{error:?}");
    assert!(error.to_string().contains("lookup-denied"));
    assert_eq!(images.calls.load(Ordering::SeqCst), 0);
    assert!(consent.offers.lock().unwrap().is_empty());
}

#[test]
fn checksum_stdout_with_an_extra_record_is_not_a_verified_image() {
    let mut sb = Sandbox::start();
    sb.fake_qshd(
        &sb.home.path().join("bin/sha256sum"),
        "/usr/bin/sha256sum; echo unexpected-record",
    );
    let error = run(
        &mut sb,
        bundled(),
        hooks(source(SCRIPT), approval(true), Arc::default()),
        &knock::Cancel::new(),
    )
    .unwrap_err();
    assert!(matches!(error, BringUpError::Verify(_)), "{error:?}");
    assert_not_started(&sb);
    assert_no_temporary(&sb);
}

#[test]
fn partial_ready_then_timeout_is_not_success_and_keeps_stderr() {
    let mut sb = Sandbox::start();
    let bytes = [
        b"#!/bin/sh\necho unfinished-ensure >&2\n".as_slice(),
        SCRIPT,
        b"exec sleep 2\n",
    ]
    .concat();
    let mut hooks = hooks(source(&bytes), approval(true), Arc::default());
    hooks.timing.ensure = std::time::Duration::from_millis(200);
    let error = run(&mut sb, bundled(), hooks, &knock::Cancel::new()).unwrap_err();
    assert!(matches!(error, BringUpError::EnsureFailed(_)), "{error:?}");
    assert!(error.to_string().contains("did not finish"));
    assert!(error.to_string().contains("stderr: unfinished-ensure"));
    assert_no_temporary(&sb);
}
