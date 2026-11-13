fn host_sentinel(mode: HostMode) -> super::super::host::HostState {
    use super::super::host::{HostLimits, HostState};
    use super::super::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
    let bytes = ByteLimits {
        channel_bytes: 100,
        session_bytes: 200,
        account_bytes: 300,
        global_bytes: 400,
    };
    let resources = ResourceLimits {
        max_reservations: 8,
        screen: ScreenLimits {
            global_cells: 1000,
            account_cells: 500,
            global_rows: 100,
            account_rows: 50,
            global_models: 10,
            account_models: 5,
        },
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let limits = HostLimits::new(resources, 2, 2, 2, 2, 100).unwrap();
    HostState::new(mode, limits).unwrap()
}
use super::*;
use std::thread;
use std::time::Duration;
use transport::session_resume::OwnerInstance;

fn config(owner: Option<OwnerInstance>, requester: OwnerRole) -> TrustedChannelConfig {
    TrustedChannelConfig {
        host: HostInstance::new([1; 16]).unwrap(),
        owner,
        requester,
        mode: HostMode::Personal {
            canonical_uid: nix::unistd::geteuid().as_raw(),
        },
        system_uid: nix::unistd::geteuid().as_raw(),
        min_version: 1,
        max_version: 1,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn admitted(
    config: TrustedChannelConfig,
    budget: &AdmissionBudget,
) -> (AdmittedChannel, AdmittedChannel) {
    let (a, b) = provision_pair(config, budget).unwrap();
    let until = deadline();
    let worker = thread::spawn(move || admit_channel(a, until));
    let b = admit_channel(b, until);
    let a = worker.join().unwrap();
    (a.unwrap(), b.unwrap())
}
#[test]
fn admission529_real_three_role_pairs_and_one_shot_frontend_evidence() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    for (owner, role) in [
        (None, OwnerRole::Frontend),
        (
            Some(OwnerInstance::new([2; 16]).unwrap()),
            OwnerRole::Frontend,
        ),
        (Some(OwnerInstance::new([2; 16]).unwrap()), OwnerRole::Owner),
    ] {
        let cfg = config(owner, role);
        let mode = cfg.mode;
        let (mut a, mut b) = admitted(cfg, &budget);
        assert_eq!(budget.in_use(), 1);
        if owner.is_none() {
            assert!(
                super::super::authorization::local_peer::authenticate_frontend(&mut b, mode)
                    .is_ok()
            );
            assert!(
                super::super::authorization::local_peer::authenticate_frontend(&mut b, mode)
                    .is_err()
            );
        } else {
            assert!(
                super::super::authorization::local_peer::authenticate_frontend(&mut a, mode)
                    .is_err()
            );
            assert!(
                super::super::authorization::local_peer::authenticate_frontend(&mut b, mode)
                    .is_err()
            );
        }
        drop((a, b));
        assert_eq!(budget.in_use(), 0);
    }
}
#[test]
fn admission529_capacity_is_shared_until_both_real_descriptors_close() {
    let _serial = SERIAL.lock().unwrap();
    assert!(AdmissionBudget::new(0).is_err());
    let budget = AdmissionBudget::new(1).unwrap();
    let cfg = config(None, OwnerRole::Frontend);
    let (a, b) = provision_pair(cfg, &budget).unwrap();
    assert!(provision_pair(cfg, &budget).is_err());
    drop(a);
    assert_eq!(budget.in_use(), 1);
    drop(b);
    assert_eq!(budget.in_use(), 0);
    drop(provision_pair(cfg, &budget).unwrap());
    assert_eq!(budget.in_use(), 0);
}
#[test]
fn admission529_absolute_deadline_stall_and_expired_attempt() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
    let start = Instant::now();
    assert!(admit_channel(a, start + Duration::from_millis(35)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(b);
    assert_eq!(budget.in_use(), 0);
    let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
    assert!(admit_channel(a, Instant::now()).is_err());
    drop(b);
    assert_eq!(budget.in_use(), 0);
}
#[test]
fn admission529_mode_mismatch_consumes_evidence_and_retains_fd() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let (a, mut b) = admitted(config(None, OwnerRole::Frontend), &budget);
    let fd = b.custody.fd.as_ref().unwrap().as_raw_fd();
    assert!(
        super::super::authorization::local_peer::authenticate_frontend(&mut b, HostMode::System)
            .is_err()
    );
    assert!(
        super::super::authorization::local_peer::authenticate_frontend(
            &mut b,
            config(None, OwnerRole::Frontend).mode
        )
        .is_err()
    );
    assert!(unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0);
    drop((a, b));
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn admission529_system_kernel_identity_is_not_target_authority_or_host_generation() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mode = HostMode::System;
    let mut host = host_sentinel(mode);
    let mut cfg = config(None, OwnerRole::Frontend);
    cfg.mode = mode;
    cfg.host = host.instance();
    let (a, mut b) = admitted(cfg, &budget);
    let peer =
        super::super::authorization::local_peer::authenticate_frontend(&mut b, mode).unwrap();
    let front = host.admit_frontend(peer).unwrap();
    assert_eq!(host.catalog_len(), 0);
    host.retire_frontend(front).unwrap();
    assert_eq!(host.catalog_len(), 0);
    drop((a, b));
    assert_eq!(budget.in_use(), 0);
}
#[test]
fn admission529_kernel_uid_mismatch_precedes_any_admission_bytes() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mut cfg = config(None, OwnerRole::Frontend);
    cfg.mode = HostMode::System;
    cfg.system_uid = nix::unistd::geteuid().as_raw().wrapping_add(1);
    assert!(provision_pair(cfg, &budget).is_err());
    assert_eq!(budget.in_use(), 0);
    cfg.system_uid = nix::unistd::geteuid().as_raw();
    let (mut a, b) = provision_pair(cfg, &budget).unwrap();
    a.config.system_uid = cfg.system_uid.wrapping_add(1);
    assert!(admit_channel(a, deadline()).is_err());
    let mut peer = &*stream(b.custody.fd.as_ref().unwrap());
    let mut bytes = [0; 128];
    assert_eq!(peer.read(&mut bytes).unwrap(), 0);
    drop(b);
    assert_eq!(budget.in_use(), 0);
}
#[test]
fn admission529_rejects_file_pipe_datagram_listener_unconnected_and_nonunix_fixtures() {
    let _serial = SERIAL.lock().unwrap();
    use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
    use std::os::unix::net::{UnixDatagram, UnixListener};
    let budget = AdmissionBudget::new(1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (pipe, pipe_peer) = nix::unistd::pipe().unwrap();
    let (dgram, dgram_peer) = UnixDatagram::pair().unwrap();
    let listener = UnixListener::bind(dir.path().join("fixture.sock")).unwrap();
    let fixtures: Vec<OwnedFd> = vec![
        tempfile::tempfile().unwrap().into(),
        pipe,
        dgram.into(),
        listener.into(),
        socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap(),
        socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap(),
    ];
    for fd in fixtures {
        let (mut a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
        // Hostile test-only replacement; original fixture custody is independently settled.
        drop(a.custody.fd.replace(fd));
        assert!(admit_channel(a, deadline()).is_err());
        drop(b);
        assert_eq!(budget.in_use(), 0);
    }
    drop((pipe_peer, dgram_peer));
}
fn malformed(owner: Option<OwnerInstance>, change: impl FnOnce(&mut Vec<u8>)) {
    let (mut sentinel_writer, mut sentinel_reader) = UnixStream::pair().unwrap();
    sentinel_reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let catalog = host_sentinel(HostMode::System);
    let catalog_instance = catalog.instance();
    let catalog_count = catalog.catalog_len();
    let budget = AdmissionBudget::new(1).unwrap();
    let (a, b) = provision_pair(config(owner, OwnerRole::Frontend), &budget).unwrap();
    let mut wire = frame(&a, a.local, true).unwrap();
    change(&mut wire);
    let mut writer = &*stream(a.custody.fd.as_ref().unwrap());
    writer.write_all(&wire).unwrap();
    drop(a);
    assert!(admit_channel(b, deadline()).is_err());
    assert_eq!(budget.in_use(), 0);
    sentinel_writer.write_all(b"ok").unwrap();
    let mut got = [0; 2];
    sentinel_reader.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ok");
    assert_eq!(catalog.instance(), catalog_instance);
    assert_eq!(catalog.catalog_len(), catalog_count);
}
#[test]
fn admission529_frozen_headers_bodies_lengths_and_early_application_are_strict() {
    let _serial = SERIAL.lock().unwrap();
    for offset in [0, 4, 6, 7, 8, 12, 28, 36, 52, 84, 86] {
        malformed(None, |wire| wire[offset] ^= 0xff);
    }
    malformed(None, |wire| wire[7] = 0x20);
    malformed(None, |wire| {
        wire[8..12].copy_from_slice(&u32::MAX.to_be_bytes())
    });
    malformed(None, |wire| wire.truncate(10));
    malformed(None, |wire| {
        wire.pop();
    });
    malformed(Some(OwnerInstance::new([2; 16]).unwrap()), |wire| {
        wire[28] ^= 0xff
    });
    malformed(Some(OwnerInstance::new([2; 16]).unwrap()), |wire| {
        wire[7] = 1
    });
}
#[test]
fn admission529_fresh_channel_refuses_cross_channel_or_replayed_offer() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(2).unwrap();
    let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
    let stale = frame(&a, a.local, true).unwrap();
    drop((a, b));
    for _ in 0..2 {
        let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
        assert_ne!(frame(&a, a.local, true).unwrap(), stale);
        let mut writer = &*stream(a.custody.fd.as_ref().unwrap());
        writer.write_all(&stale).unwrap();
        assert!(admit_channel(b, deadline()).is_err());
        drop(a);
        assert_eq!(budget.in_use(), 0);
    }
}
#[test]
fn admission529_partial_reads_preserve_following_qsho_hello_bytes() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let owner = OwnerInstance::new([2; 16]).unwrap();
    let (a, b) = provision_pair(config(Some(owner), OwnerRole::Frontend), &budget).unwrap();
    let offer = frame(&a, a.local, true).unwrap();
    let hello = protocol::encode(&OwnerFrame {
        header: OwnerHeader {
            role: a.local,
            host: a.config.host,
            owner,
            request_id: 2,
        },
        message: OwnerMessage::Hello {
            min_version: 1,
            max_version: 1,
        },
    })
    .unwrap();
    let expected = hello.clone();
    let worker = thread::spawn(move || {
        let mut writer = &*stream(a.custody.fd.as_ref().unwrap());
        for byte in offer {
            writer.write_all(&[byte]).unwrap();
        }
        writer.write_all(&hello).unwrap();
        let mut ack = vec![0; frame(&a, a.peer, false).unwrap().len()];
        transfer(a.custody.fd.as_ref().unwrap(), &mut ack, false, deadline()).unwrap();
        assert_eq!(ack, frame(&a, a.peer, false).unwrap());
        a
    });
    let admitted = admit_channel(b, deadline());
    let a = worker.join().unwrap();
    let b = admitted.unwrap();
    let mut got = vec![0; expected.len()];
    transfer(b.custody.fd.as_ref().unwrap(), &mut got, false, deadline()).unwrap();
    assert_eq!(got, expected);
    drop((a, b));
    assert_eq!(budget.in_use(), 0);
}
#[test]
fn admission529_dribbled_input_cannot_extend_absolute_deadline_and_worker_is_joined() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
    let offer = frame(&a, a.local, true).unwrap();
    let start = Instant::now();
    let worker = thread::spawn(move || {
        let mut writer = &*stream(a.custody.fd.as_ref().unwrap());
        for byte in offer {
            if writer.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(8));
        }
        drop(a);
    });
    let result = admit_channel(b, start + Duration::from_millis(35));
    let elapsed = start.elapsed();
    worker.join().unwrap();
    assert!(result.is_err());
    assert!(elapsed < Duration::from_secs(1));
    assert_eq!(budget.in_use(), 0);
}
#[test]
fn admission529_invalid_roles_ranges_and_budget_overflow_refuse_without_allocation() {
    let _serial = SERIAL.lock().unwrap();
    assert!(AdmissionBudget::new(usize::MAX).is_err());
    let budget = AdmissionBudget::new(1).unwrap();
    let mut cfg = config(None, OwnerRole::Host);
    assert!(provision_pair(cfg, &budget).is_err());
    cfg = config(None, OwnerRole::Frontend);
    cfg.min_version = 2;
    assert!(provision_pair(cfg, &budget).is_err());
    cfg.min_version = 1;
    cfg.max_version = 0;
    assert!(provision_pair(cfg, &budget).is_err());
    assert_eq!(budget.in_use(), 0);
}

static SERIAL: Mutex<()> = Mutex::new(());
static CLOSE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static SOURCE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static REUSED: Mutex<Option<OwnedFd>> = Mutex::new(None);
// Deliberate test injection: actually closes once, then reports uncertainty.
// This is not a claim that a native kernel close failed.
fn close_with_injected_uncertainty(fd: RawFd) -> bool {
    use std::sync::atomic::Ordering;
    CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
    assert!(close_once(fd));
    let replacement = unsafe {
        nix::libc::fcntl(
            SOURCE_FD.load(Ordering::SeqCst),
            nix::libc::F_DUPFD_CLOEXEC,
            fd,
        )
    };
    assert_eq!(
        replacement, fd,
        "serialized fixture must really reuse the retired number"
    );
    *REUSED.lock().unwrap() = Some(unsafe { OwnedFd::from_raw_fd(replacement) });
    false
}
#[test]
fn admission529_injected_close_uncertainty_retains_charge_and_never_retries_reused_fd() {
    let _serial = SERIAL.lock().unwrap();
    use std::sync::atomic::Ordering;
    const CHILD: &str = "QSH_ADMISSION529_UNCERTAINTY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        use std::process::{Command, Stdio};
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","session_owner::local_channel::tests::admission529_injected_close_uncertainty_retains_charge_and_never_retries_reused_fd","--nocapture"]).env(CHILD,"1").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let pid = child.id();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("owned uncertainty fixture exceeded deadline; child reaped")
            }
            thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "isolated fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!(
            "admission529 isolated uncertainty child {pid} reaped: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // Exactly one selected test in an owned process: unrelated library tests
    // cannot allocate numbers in this FD namespace during deliberate reuse.
    #[cfg(target_os = "linux")]
    let baseline = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let budget = AdmissionBudget::new(1).unwrap();
    let (mut a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
    let (source, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    SOURCE_FD.store(source.as_raw_fd(), Ordering::SeqCst);
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    let number = a.custody.fd.as_ref().unwrap().as_raw_fd();
    a.custody.closer = close_with_injected_uncertainty;
    drop(a);
    drop(b);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(budget.in_use(), 1);
    assert_eq!(budget.state.lock().unwrap().uncertain_ends, 1);
    assert!(provision_pair(config(None, OwnerRole::Frontend), &budget).is_err());
    let replacement = REUSED.lock().unwrap().take().unwrap();
    assert_eq!(replacement.as_raw_fd(), number);
    let socket = stream(&replacement);
    let mut writer = &*socket;
    writer.write_all(b"sentinel").unwrap();
    let mut bytes = [0; 8];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"sentinel");
    drop(replacement);
    drop((source, peer));
    assert_eq!(budget.in_use(), 1);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
    #[cfg(target_os = "linux")]
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        baseline
    );
    eprintln!("fixture descriptors independently settled; unresolved production pair charge=1; close calls=1; reused descriptor remained usable");
}

#[test]
fn admission529_requester_rejects_mismatched_or_replayed_ack() {
    let _serial = SERIAL.lock().unwrap();
    for offset in [0, 4, 6, 7, 12, 28, 36, 52, 84] {
        let budget = AdmissionBudget::new(1).unwrap();
        let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
        let mut ack = frame(&b, b.local, false).unwrap();
        ack[offset] ^= 0xff;
        let mut writer = &*stream(b.custody.fd.as_ref().unwrap());
        writer.write_all(&ack).unwrap();
        assert!(admit_channel(a, deadline()).is_err());
        drop(b);
        assert_eq!(budget.in_use(), 0);
    }
}
#[test]
fn admission529_nonblocking_write_backpressure_obeys_same_absolute_deadline() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let (a, b) = provision_pair(config(None, OwnerRole::Frontend), &budget).unwrap();
    nix::sys::socket::setsockopt(
        a.custody.fd.as_ref().unwrap(),
        nix::sys::socket::sockopt::SndBuf,
        &1024,
    )
    .unwrap();
    let mut writer = &*stream(a.custody.fd.as_ref().unwrap());
    let mut filled = 0;
    loop {
        match writer.write(&[0; 4096]) {
            Ok(n) => {
                assert!(n > 0);
                filled += n;
                assert!(filled < 1024 * 1024)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("fixture buffer fill failed: {e}"),
        }
    }
    let start = Instant::now();
    assert!(matches!(
        admit_channel(a, start + Duration::from_millis(35)),
        Err(AdmissionError::Deadline)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(b);
    assert_eq!(budget.in_use(), 0);
}

// Removing the retained Offer/Ack state must reject the first post-admission
// Begin; reinitializing it must incorrectly accept replayed admission/id 1.
#[test]
fn authdispatch529_real_admission_handoff_is_one_shot_and_keeps_request_history() {
    use super::super::host_auth_contract::{AuthMethod, HostAuthMessage};
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    for mode in [config(None, OwnerRole::Frontend).mode, HostMode::System] {
        let method = if mode == HostMode::System {
            AuthMethod::System
        } else {
            AuthMethod::Personal
        };
        let wrong = if mode == HostMode::System {
            AuthMethod::Personal
        } else {
            AuthMethod::System
        };
        let mut host = host_sentinel(mode);
        let mut cfg = config(None, OwnerRole::Frontend);
        cfg.host = host.instance();
        cfg.mode = mode;
        let (peer, channel) = admitted(cfg, &budget);
        let mut dispatch = channel.into_host_dispatch(&mut host, mode, 2).unwrap();
        assert_eq!(budget.in_use(), 1);
        let begin = |id, method| HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: cfg.host,
                request_id: id,
            },
            message: HostMessage::Authentication(HostAuthMessage::Begin { method }),
        };
        assert!(dispatch.receive_at(&begin(1, method), 0).is_err());
        assert!(dispatch.receive_at(&begin(2, wrong), 0).is_err());
        dispatch.receive_at(&begin(2, method), 0).unwrap();
        assert!(dispatch.receive_at(&begin(2, method), 0).is_err());
        assert_eq!(host.catalog_len(), 0);
        dispatch.retire(&mut host).unwrap();
        assert_eq!(budget.in_use(), 1);
        drop(peer);
        assert_eq!(budget.in_use(), 0);
    }
}

// Borrowed operations must leave both descriptor ownership and trailing
// post-admission data intact, and must never block on an empty socket.
#[test]
fn authdispatch529_borrowed_io_keeps_custody_and_post_admission_bytes() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mode = config(None, OwnerRole::Frontend).mode;
    let mut host = host_sentinel(mode);
    let mut cfg = config(None, OwnerRole::Frontend);
    cfg.host = host.instance();
    let (peer, channel) = admitted(cfg, &budget);
    let mut dispatch = channel.into_host_dispatch(&mut host, mode, 2).unwrap();
    let socket = stream(peer.custody.fd.as_ref().unwrap());
    let mut other = &*socket;
    other.write_all(b"after-admission").unwrap();
    let mut bytes = [0; 15];
    assert_eq!(dispatch.read(&mut bytes).unwrap(), 15);
    assert_eq!(&bytes, b"after-admission");
    assert_eq!(
        dispatch.read(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(dispatch.write(b"reply").unwrap(), 5);
    let mut reply = [0; 5];
    other.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"reply");
    assert_eq!(budget.in_use(), 1);
    dispatch.retire(&mut host).unwrap();
    drop((socket, peer));
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn authdispatch529_wrong_host_mode_role_and_spent_evidence_refuse_handoff() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mode = config(None, OwnerRole::Frontend).mode;
    for case in 0..4 {
        let mut host = host_sentinel(mode);
        let mut cfg = config(None, OwnerRole::Frontend);
        if case != 0 {
            cfg.host = host.instance();
        }
        let (peer, mut channel) = admitted(cfg, &budget);
        if case == 3 {
            super::super::authorization::local_peer::authenticate_frontend(&mut channel, mode)
                .unwrap();
        }
        let result = if case == 2 {
            peer.into_host_dispatch(&mut host, mode, 2)
        } else {
            drop(peer);
            channel.into_host_dispatch(
                &mut host,
                if case == 1 { HostMode::System } else { mode },
                2,
            )
        };
        assert!(result.is_err());
        assert_eq!(host.catalog_len(), 0);
    }
    assert_eq!(budget.in_use(), 0);
}

// Dropping descriptor custody must not manufacture logical retirement in HostState.
#[test]
fn authdispatch529_drop_closes_owned_fd_without_refunding_host_registration() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mode = config(None, OwnerRole::Frontend).mode;
    let mut host = host_sentinel(mode);
    let mut cfg = config(None, OwnerRole::Frontend);
    cfg.host = host.instance();
    let mut retained = Vec::new();
    for _ in 0..2 {
        let (peer, channel) = admitted(cfg, &budget);
        let dispatch = channel.into_host_dispatch(&mut host, mode, 2).unwrap();
        retained.push(dispatch.frontend());
        drop(dispatch);
        let socket = stream(peer.custody.fd.as_ref().unwrap());
        assert_eq!((&*socket).read(&mut [0; 1]).unwrap(), 0);
        drop((socket, peer));
        assert_eq!(budget.in_use(), 0);
    }
    let (peer, channel) = admitted(cfg, &budget);
    assert!(channel.into_host_dispatch(&mut host, mode, 2).is_err());
    drop(peer);
    assert_eq!(budget.in_use(), 0);
    for frontend in retained {
        host.retire_frontend(frontend).unwrap();
    }
    let (peer, channel) = admitted(cfg, &budget);
    channel
        .into_host_dispatch(&mut host, mode, 2)
        .unwrap()
        .retire(&mut host)
        .unwrap();
    drop(peer);
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn authdispatch529_completed_wire_admission_cannot_be_replayed_after_handoff() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mode = config(None, OwnerRole::Frontend).mode;
    let mut host = host_sentinel(mode);
    let mut cfg = config(None, OwnerRole::Frontend);
    cfg.host = host.instance();
    let (a, b) = provision_pair(cfg, &budget).unwrap();
    let offered = host_protocol::HostDecoder::new()
        .push(&frame(&a, OwnerRole::Frontend, true).unwrap())
        .unwrap()
        .pop()
        .unwrap();
    let acknowledged = host_protocol::HostDecoder::new()
        .push(&frame(&b, OwnerRole::Host, false).unwrap())
        .unwrap()
        .pop()
        .unwrap();
    let until = deadline();
    let worker = thread::spawn(move || admit_channel(a, until));
    let channel = admit_channel(b, until).unwrap();
    let peer = worker.join().unwrap().unwrap();
    let mut dispatch = channel.into_host_dispatch(&mut host, mode, 2).unwrap();
    assert!(dispatch.receive_at(&offered, 0).is_err());
    assert!(dispatch.send_at(&acknowledged, 0).is_err());
    dispatch.retire(&mut host).unwrap();
    drop(peer);
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn authdispatch529_invalid_correlation_limit_precedes_host_registration() {
    let _serial = SERIAL.lock().unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let mode = config(None, OwnerRole::Frontend).mode;
    let mut host = host_sentinel(mode);
    let mut cfg = config(None, OwnerRole::Frontend);
    cfg.host = host.instance();
    for limit in [0, 65, usize::MAX] {
        let (peer, channel) = admitted(cfg, &budget);
        assert!(channel.into_host_dispatch(&mut host, mode, limit).is_err());
        drop(peer);
        assert_eq!(budget.in_use(), 0);
    }
    let (peer, channel) = admitted(cfg, &budget);
    let dispatch = channel.into_host_dispatch(&mut host, mode, 2).unwrap();
    let frontend = dispatch.frontend();
    // The generation/registration is issued by this actual host, and can own
    // a real bounded intent. No decoded Begin or test peer creates authority.
    let _intent = host.begin_authentication(frontend, 0, 10).unwrap();
    dispatch.retire(&mut host).unwrap();
    drop(peer);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(host.catalog_len(), 0);
}
