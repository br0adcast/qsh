use super::super::authorization::HostMode;
use super::super::local_channel::{self, AdmissionBudget, TrustedChannelConfig};
use super::super::protocol::OwnerRole;
use super::record::{LaunchDeadline, SetupReceiver, SetupRecord};
use std::time::{Duration, Instant};
use transport::session_resume::HostInstance;

fn golden() -> [u8; 112] {
    let mut bytes = [0; 112];
    bytes[..8].copy_from_slice(b"QSHL5291");
    bytes[8..10].copy_from_slice(&1u16.to_be_bytes());
    bytes[10..12].copy_from_slice(&112u16.to_be_bytes());
    bytes[12..28].fill(1);
    bytes[28..44].fill(2);
    bytes[44..76].fill(3);
    bytes[76..80].copy_from_slice(&1001u32.to_be_bytes());
    bytes[80] = 2;
    bytes[81] = 1;
    bytes[82..84].copy_from_slice(&1u16.to_be_bytes());
    bytes[84..86].copy_from_slice(&1u16.to_be_bytes());
    bytes[88..96].copy_from_slice(&1_000_000u64.to_be_bytes());
    bytes[96..104].copy_from_slice(&1u64.to_be_bytes());
    bytes
}

#[test]
fn launch529_record_exact_shape_and_binding() {
    let bytes = golden();
    let record = SetupRecord::decode(&bytes, 1001, 999_999).unwrap();
    assert_eq!(record.encode(), bytes);
    assert_eq!(record.host, HostInstance::new([1; 16]).unwrap());
    assert_eq!(record.channel, [2; 16]);
    assert_eq!(record.challenge, [3; 32]);
    assert_eq!(record.uid, 1001);
    assert_eq!(record.deadline, 1_000_000);
    assert!(SetupRecord::decode(&bytes, 1002, 0).is_err());
    assert!(SetupRecord::decode(&bytes, 0, 0).is_err());
}

#[test]
fn launch529_record_rejects_every_unsupported_field() {
    let original = golden();
    for n in 0..112 {
        assert!(SetupRecord::decode(&original[..n], 1001, 0).is_err());
    }
    let mut extra = original.to_vec();
    extra.push(0);
    assert!(SetupRecord::decode(&extra, 1001, 0).is_err());
    for offset in [0, 8, 10, 80, 81, 82, 84, 86, 96, 104] {
        let mut bytes = original;
        bytes[offset] ^= 1;
        assert!(
            SetupRecord::decode(&bytes, 1001, 0).is_err(),
            "unsupported offset {offset}"
        );
    }
    for range in [12..28, 28..44, 44..76, 76..80] {
        let mut bytes = original;
        bytes[range].fill(0);
        assert!(SetupRecord::decode(&bytes, 1001, 0).is_err());
    }
    assert!(SetupRecord::decode(&original, 1001, 1_000_000).is_err());
    assert!(SetupRecord::decode(&original, 1001, u64::MAX).is_err());
}

#[test]
fn launch529_deadline_is_absolute_across_partial_setup() {
    let start = Instant::now();
    let deadline =
        LaunchDeadline::from_samples(start + Duration::from_nanos(100), start, 900).unwrap();
    assert_eq!(deadline.absolute(), 1000);
    assert!(LaunchDeadline::from_samples(start, start, 900).is_err());
    assert!(
        LaunchDeadline::from_samples(start + Duration::from_nanos(100), start, u64::MAX - 99)
            .is_err()
    );
    let local = LaunchDeadline::local_from_samples(1000, 950, start).unwrap();
    assert_eq!(local, start + Duration::from_nanos(50));
    assert!(LaunchDeadline::local_from_samples(1000, 1000, start).is_err());
    let mut bytes = golden();
    bytes[88..96].copy_from_slice(&1000u64.to_be_bytes());
    let mut receiver = SetupReceiver::new(1000);
    assert!(receiver.push(&bytes[..16], 900, 1001).unwrap().is_none());
    assert!(receiver.push(&bytes[16..32], 999, 1001).unwrap().is_none());
    assert!(
        receiver.push(&bytes[32..], 1000, 1001).is_err(),
        "dribble cannot extend deadline"
    );
    let mut receiver = SetupReceiver::new(1000);
    assert!(receiver.push(&bytes, 999, 1001).unwrap().is_some());
    assert!(receiver.push(&[], 999, 1001).is_err(), "record is one use");
}

fn config() -> TrustedChannelConfig {
    let uid = unsafe { nix::libc::geteuid() };
    TrustedChannelConfig {
        host: HostInstance::new([4; 16]).unwrap(),
        owner: None,
        requester: OwnerRole::Frontend,
        mode: HostMode::Personal { canonical_uid: uid },
        system_uid: uid,
        min_version: 1,
        max_version: 1,
    }
}

#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_frontend_transfer_cannot_restore_host_or_owner() {
    let budget = AdmissionBudget::new(1).unwrap();
    let (frontend, host) = local_channel::provision_pair(config(), &budget).unwrap();
    assert!(
        local_channel::launch::split_frontend(host).is_err(),
        "host expectation cannot be serialized"
    );
    drop(frontend);
    assert_eq!(budget.in_use(), 0);
    let mut wrong = config();
    wrong.mode = HostMode::System;
    let (frontend, host) = local_channel::provision_pair(wrong, &budget).unwrap();
    assert!(local_channel::launch::split_frontend(frontend).is_err());
    drop(host);
    assert_eq!(budget.in_use(), 0);
    let (frontend, host) = local_channel::provision_pair(config(), &budget).unwrap();
    let (prepared, remote) = local_channel::launch::split_frontend(frontend).unwrap();
    assert_eq!(prepared.setup(1000).uid, unsafe { nix::libc::geteuid() });
    let uid = unsafe { libc::geteuid() };
    assert!(prepared.test_check_uid(uid).is_ok());
    assert!(
        prepared.test_check_uid(0).is_err(),
        "root change refuses before spawn"
    );
    assert!(
        prepared.test_check_uid(uid.wrapping_add(1)).is_err(),
        "foreign euid refuses before spawn"
    );
    drop(prepared);
    drop(host);
    assert_eq!(
        budget.in_use(),
        1,
        "remote custody remains private and charged"
    );
    drop(remote);
    assert_eq!(
        budget.in_use(),
        1,
        "dropping an observation is not physical settlement"
    );
}

#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_transferred_end_stays_charged() {
    prepare_observation_sites();
    let budget = AdmissionBudget::new(1).unwrap();
    let (frontend, host) = local_channel::provision_pair(config(), &budget).unwrap();
    let (prepared, remote) = local_channel::launch::split_frontend(frontend).unwrap();
    assert!(local_channel::provision_pair(config(), &budget).is_err());
    let record = prepared.setup(1000).encode();
    assert_eq!(record.len(), 112);
    drop(prepared);
    drop(host);
    assert_eq!(budget.in_use(), 1);
    drop(remote);
    assert_eq!(budget.in_use(), 1);
    // Observation of an active preparation must retain every exact object/fd.
    // Host's derived Debug snapshot includes its sealed OwnedFd and pair data;
    // comparison needs no raw-fd access/restoration API on ExpectedAdmission.
    use std::os::fd::AsRawFd;
    let local = |fd: &local_channel::launch::LocalFd| {
        (std::ptr::from_ref(fd), fd.fd().unwrap().as_raw_fd())
    };
    let custody = |c: &super::Capsule| {
        (
            c.host
                .as_ref()
                .map(|host| (std::ptr::from_ref(host), format!("{host:?}"))),
            c.frontend
                .as_ref()
                .map(|end| (std::ptr::from_ref(end), local(&end.fd))),
            c.setup.as_ref().map(local),
            c.setup_child.as_ref().map(local),
            c.duplicates.each_ref().map(|fd| fd.as_ref().map(local)),
            c.remote.as_ref().map(std::ptr::from_ref),
            std::sync::Arc::as_ptr(&c.control),
        )
    };
    for expire in [false, true] {
        let mut launches = super::FrontendLaunches::new(1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let handle = launches.prepare(config(), deadline).unwrap();
        let capsule = launches.find(&handle).unwrap();
        let original = custody(&capsule.lock().unwrap());
        for now in [
            deadline - Duration::from_secs(2),
            deadline - Duration::from_secs(1),
        ] {
            {
                let mut c = capsule.lock().unwrap();
                assert_eq!(c.poll_at(now), super::LaunchProgress::Preparing);
                assert!(!c.cancelled());
                assert_eq!(c.wait, super::WaitState::NotCreated);
                assert!(c.export == super::ExportDisposition::LocalOnly);
                assert!(c.child.is_none() && !c.eof && !c.started);
                assert_eq!(
                    custody(&c),
                    original,
                    "pre-start polling preserves exact custody"
                );
                c.frontend.as_ref().unwrap().for_spawn().unwrap();
                assert!(c.first_unknown.is_none());
                let observed = c.observation();
                let busy = c.remote.as_ref().unwrap().test_busy_observation();
                assert_eq!(busy.local, local_channel::launch::ObservationAccess::Busy);
                assert!(busy.live.is_none() && busy.uncertain.is_none());
                assert_eq!(
                    c.observation(),
                    observed,
                    "diagnostic access cannot change custody/debt"
                );
                assert_eq!(custody(&c), original);
            }
            assert_eq!(launches.in_use(), 1);
            assert_eq!(launches.budget.in_use(), 1);
        }
        let progress = if expire {
            capsule.lock().unwrap().poll_at(deadline)
        } else {
            launches.cancel(&handle);
            launches.poll(&handle)
        };
        assert_eq!(progress, super::LaunchProgress::Settled);
        {
            let c = capsule.lock().unwrap();
            assert!(c.cancelled() && !c.eof && c.child.is_none());
            assert_eq!(c.wait, super::WaitState::NotCreated);
            assert!(c.host.is_none() && c.frontend.is_none() && c.setup.is_none());
            assert!(c.setup_child.is_none() && c.duplicates.iter().all(Option::is_none));
            assert!(c.remote.is_none());
        }
        assert_eq!(launches.in_use(), 0);
        assert_eq!(launches.budget.in_use(), 0);
        let next = launches
            .prepare(config(), Instant::now() + Duration::from_secs(60))
            .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&handle.control, &next.control));
        assert_eq!(launches.in_use(), 1);
        assert_eq!(launches.budget.in_use(), 1);
        launches.cancel(&next);
        assert_eq!(launches.poll(&next), super::LaunchProgress::Settled);
    }
    // A preparation failure has no returned handle. Known no-export closure
    // must refund immediately; uncertain physical closure must retain debt.
    for after_allocation in [false, true] {
        for uncertain in [false, true] {
            let mut launches = super::FrontendLaunches::new(1).unwrap();
            launches.setup_pair_failure = !after_allocation;
            launches.setup_failure_after_allocation = after_allocation;
            launches.uncertain_preparation_close = uncertain;
            assert!(matches!(
                launches.prepare(config(), Instant::now() + Duration::from_secs(1)),
                Err(local_channel::AdmissionError::Unavailable)
            ));
            assert_eq!(launches.in_use(), usize::from(uncertain));
            assert_eq!(launches.budget.in_use(), usize::from(uncertain));
            launches.setup_pair_failure = false;
            launches.setup_failure_after_allocation = false;
            let next = launches.prepare(config(), Instant::now() + Duration::from_secs(1));
            if uncertain {
                assert!(matches!(next, Err(local_channel::AdmissionError::Capacity)));
            } else {
                let handle = next.unwrap();
                launches.cancel(&handle);
                assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
            }
        }
    }
}

#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_cancel_before_and_after_start_wins_late_admission() {
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap_or_else(|error| {
            eprintln!("{}", launches.prepare_observer.render(error));
            panic!("preparation failed: {error:?}");
        });
    launches.cancel(&handle);
    assert!(
        !launches.test_publish(&handle),
        "cancelled setup cannot publish late admission"
    );
    assert_ne!(launches.poll(&handle), super::LaunchProgress::Admitted);
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    launches.test_started(&handle);
    launches.cancel(&handle);
    assert!(!launches.test_publish(&handle));
    assert_eq!(launches.in_use(), 1);
    launches.test_wait(&handle, false);
    assert_ne!(launches.poll(&handle), super::LaunchProgress::Settled);
    launches.test_eof(&handle);
    assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
    assert_eq!(launches.in_use(), 0);
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_handle_drop_keeps_physical_custody() {
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    launches.test_started(&handle);
    let weak = launches.test_weak(&handle);
    drop(handle);
    assert_eq!(launches.in_use(), 1);
    assert!(weak.upgrade().is_some());
    assert!(launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .is_err());
    launches.test_finish_dropped();
    assert_eq!(launches.in_use(), 0);
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_wait_and_eof_are_independent_receipts() {
    for eof_first in [true, false] {
        let mut launches = super::FrontendLaunches::new(1).unwrap();
        let handle = launches
            .prepare(config(), Instant::now() + Duration::from_secs(1))
            .unwrap();
        launches.test_started(&handle);
        launches.cancel(&handle);
        if eof_first {
            launches.test_eof(&handle);
        } else {
            launches.test_wait(&handle, false);
        }
        assert_ne!(launches.poll(&handle), super::LaunchProgress::Settled);
        assert_eq!(launches.in_use(), 1, "one receipt never refunds");
        if eof_first {
            launches.test_wait(&handle, false);
        } else {
            launches.test_eof(&handle);
        }
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
        assert_eq!(launches.in_use(), 0);
    }
    reset_read_receipt_orders();
    shutdown_disconnection_receipt_orders();
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_lost_wait_and_uncertain_close_never_refund() {
    for lost_wait in [true, false] {
        let mut launches = super::FrontendLaunches::new(1).unwrap();
        let handle = launches
            .prepare(config(), Instant::now() + Duration::from_secs(1))
            .unwrap();
        launches.test_started(&handle);
        launches.cancel(&handle);
        launches.test_eof(&handle);
        launches.test_wait(&handle, lost_wait);
        if !lost_wait {
            launches.test_uncertain_close(&handle);
        }
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Unknown);
        assert_eq!(launches.in_use(), 1);
        let first = launches.observation(&handle);
        let event = first.first.unwrap();
        assert_eq!(
            event.origin,
            if lost_wait {
                super::observation::Origin::ModeledLostWait
            } else {
                super::observation::Origin::RemoteSettlement
            }
        );
        assert!(
            event.errno.is_none(),
            "modeled wait/boolean close carries no actual errno"
        );
        if lost_wait {
            assert!(!event.snapshot.eof);
        }
        assert!(first.current.unwrap().eof);
        assert_eq!(
            first.current.unwrap().debt_sample,
            super::observation::DebtSample::NotObserved
        );
        assert!(first.current.unwrap().debt.is_none());
        assert!(event.snapshot.debt.is_some());
        assert!(!first.current.unwrap().kill_attempted);
        assert_eq!(launches.budget.in_use(), 1);
        launches.cancel(&handle);
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Unknown);
        assert_eq!(launches.observation(&handle).first, first.first);
        assert_eq!(launches.budget.in_use(), 1);
    }
    reset_uncertainties_stay_charged();
    shutdown_uncertainties_stay_charged();
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_foreign_handle_cannot_cancel_or_settle() {
    let mut a = super::FrontendLaunches::new(1).unwrap();
    let mut b = super::FrontendLaunches::new(1).unwrap();
    let handle = a
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    a.test_started(&handle);
    b.cancel(&handle);
    assert_eq!(b.poll(&handle), super::LaunchProgress::Unknown);
    assert!(b.start(&handle).is_err());
    assert!(
        a.test_publish(&handle),
        "foreign registry cannot cancel exact owner"
    );
    assert_eq!(a.in_use(), 1);
    a.cancel(&handle);
    a.test_eof(&handle);
    a.test_wait(&handle, false);
    assert_eq!(a.poll(&handle), super::LaunchProgress::Settled);
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_registry_drop_quarantines_unsettled_debt() {
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    launches.test_started(&handle);
    let weak = launches.test_weak(&handle);
    drop(launches);
    assert!(
        weak.upgrade().is_some(),
        "registry Drop retains physical capsule, not just a charge"
    );
    assert!(!super::FrontendLaunches::test_quarantine_is_settled(&weak));
    super::FrontendLaunches::test_release_quarantine(&weak);
}

#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_prefix_stall_and_dribble_retire_without_reply() {
    for prefix_len in [0, 16, 95] {
        let mut launches = super::FrontendLaunches::new(1).unwrap();
        let handle = launches
            .prepare(config(), Instant::now() + Duration::from_secs(1))
            .unwrap();
        launches.test_started(&handle);
        {
            let capsule = launches.find(&handle).unwrap();
            let c = capsule.lock().unwrap();
            let record = c.record;
            if prefix_len != 0 {
                local_channel::launch::test_write(
                    c.setup.as_ref().unwrap().fd().unwrap(),
                    &record[..prefix_len],
                )
                .unwrap();
                let mut received = [0; 96];
                assert_eq!(
                    local_channel::launch::read(
                        c.setup_child.as_ref().unwrap().fd().unwrap(),
                        &mut received
                    )
                    .unwrap(),
                    prefix_len
                );
                assert_eq!(&received[..prefix_len], &record[..prefix_len]);
            }
        }
        launches.test_expire(&handle);
        assert!(
            !launches.test_publish(&handle),
            "deadline retires without a child reply"
        );
        assert_eq!(launches.in_use(), 1);
        assert_eq!(launches.budget.in_use(), 1);
        launches.test_wait(&handle, false);
        assert_ne!(launches.poll(&handle), super::LaunchProgress::Settled);
        launches.test_eof(&handle);
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
        assert_eq!(launches.budget.in_use(), 0);
    }
}
#[test]
fn launch529_known_prefix_deadline_does_not_refresh_final_bytes() {
    let mut bytes = golden();
    bytes[88..96].copy_from_slice(&1000u64.to_be_bytes());
    assert_eq!(
        SetupRecord::prefix_deadline(&bytes[..96], 1001, 999).unwrap(),
        1000
    );
    assert!(SetupRecord::prefix_deadline(&bytes[..96], 1001, 1000).is_err());
    let mut invalid = bytes;
    invalid[80] = 1;
    assert!(SetupRecord::prefix_deadline(&invalid[..96], 1001, 999).is_err());
    let mut receiver = SetupReceiver::new(1000);
    assert!(receiver.push(&bytes[..96], 999, 1001).unwrap().is_none());
    assert!(receiver.push(&bytes[96..], 1000, 1001).is_err());
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_setup_sockets_refuse_stall_extra_cancel_and_invalid_types() {
    use std::os::fd::OwnedFd;
    let uid = unsafe { libc::geteuid() };
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd: OwnedFd = a.into();
    local_channel::launch::validate_personal_fd(&fd, uid).unwrap();
    assert!(local_channel::launch::read_setup(&fd, &mut [0; 112], Instant::now()).is_err());
    let regular: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    assert!(local_channel::launch::validate_personal_fd(&regular, uid).is_err());
    let (datagram, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let datagram: OwnedFd = datagram.into();
    assert!(local_channel::launch::validate_personal_fd(&datagram, uid).is_err());
    let directory = tempfile::tempdir().unwrap();
    let listener: OwnedFd = std::os::unix::net::UnixListener::bind(directory.path().join("s"))
        .unwrap()
        .into();
    assert!(local_channel::launch::validate_personal_fd(&listener, uid).is_err());
    let mut extra = golden().to_vec();
    extra.push(0);
    assert!(SetupReceiver::new(1_000_000).push(&extra, 0, 1001).is_err());
}
#[test]
fn launch529_private_marker_routing_is_exact() {
    use std::ffi::OsString;
    assert!(super::child::recognizes(&[OsString::from(super::MARKER)])
        .unwrap()
        .is_ok());
    assert!(
        super::child::recognizes(&[OsString::from(super::MARKER), OsString::from("extra")])
            .unwrap()
            .is_err()
    );
    for command in [
        "serve",
        "transport-ensure",
        "transport-resume",
        "--service-installed-helper",
    ] {
        assert!(super::child::recognizes(&[OsString::from(command)]).is_none());
    }
    assert!(super::child::recognizes(&[]).is_none());
}
#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_poisoned_registry_keeps_exact_capsule_and_debt() {
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    let weak = launches.test_weak(&handle);
    let capsule = weak.upgrade().unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = capsule.lock().unwrap();
        panic!("injected capsule poison");
    }));
    assert_eq!(launches.poll(&handle), super::LaunchProgress::Unknown);
    assert_eq!(launches.in_use(), 1);
    let report = launches.observation(&handle);
    assert_eq!(
        report.unavailable,
        Some(super::observation::Origin::CapsulePoisoned)
    );
    assert!(report.first.is_none() && report.current.is_none());
    drop(capsule);
    drop(launches);
    assert!(
        weak.upgrade().is_some(),
        "poison cannot drop the last physical owner"
    );
    let c = weak.upgrade().unwrap();
    let mut c = c.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(c.progress, super::LaunchProgress::Unknown);
    assert_eq!(
        c.remote.as_ref().unwrap().test_in_use(),
        1,
        "poison keeps original remote charge"
    );
    c.close_child_copies();
    c.setup = None;
    c.host = None;
    c.quarantine = None;
}

#[test]
#[ignore = "ordinary nonroot owned-FD fixture; explicitly selected in maintained CI"]
fn launch529_known_extra_local_copy_is_pending_not_unknown() {
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(1))
        .unwrap();
    let mut extra = {
        let c = launches.find(&handle).unwrap();
        let c = c.lock().unwrap();
        c.setup.as_ref().unwrap().duplicate().unwrap()
    };
    launches.test_started(&handle);
    launches.cancel(&handle);
    launches.test_eof(&handle);
    launches.test_wait(&handle, false);
    assert_eq!(
        launches.poll(&handle),
        super::LaunchProgress::Closing,
        "a known retained copy is pending physical custody"
    );
    assert_eq!(launches.in_use(), 1);
    assert_eq!(launches.budget.in_use(), 1);
    extra.close();
    assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
    assert_eq!(launches.budget.in_use(), 0);
}

// Synthetic scalar fixtures exercise the same observer as native failures;
// no syscall errno, child or terminal receipt is claimed by these controls.
fn diagnostic_snapshot(status: Option<&std::process::ExitStatus>) -> super::observation::Snapshot {
    super::observation::Snapshot {
        export: super::ExportDisposition::Owned,
        wait: super::WaitState::Pending,
        status: super::observation::Status::capture(status),
        eof: false,
        cancelled: false,
        started: true,
        kill_attempted: false,
        write_shutdown: false,
        presence: [true; 9],
        debt_sample: super::observation::DebtSample::NotObserved,
        debt: None,
    }
}
#[test]
fn launch529_unknown_first_observation_is_sticky() {
    use super::observation::{self as d, Event, Origin};
    let mut first = None;
    let initial = Event {
        origin: Origin::SetupRead,
        errno: Some(123),
        snapshot: diagnostic_snapshot(None),
    };
    d::record(&mut first, initial);
    use std::os::unix::process::ExitStatusExt;
    let terminal = std::process::ExitStatus::from_raw(9 << 8);
    let mut later = diagnostic_snapshot(Some(&terminal));
    later.eof = true;
    later.wait = super::WaitState::Terminal;
    d::record(
        &mut first,
        Event {
            origin: Origin::ChildWait,
            errno: Some(456),
            snapshot: later,
        },
    );
    assert_eq!(
        first.unwrap().origin,
        Origin::SetupRead,
        "first actual uncertainty is immutable"
    );
    assert_eq!(first.unwrap().errno, Some(123));
    assert!(!first.unwrap().snapshot.eof);
    assert_eq!(first.unwrap().snapshot.wait, super::WaitState::Pending);
    assert!(later.eof);
    assert_eq!(later.status.code, Some(9));
    assert!(!first.unwrap().snapshot.status.present);
    assert_eq!(first.unwrap().snapshot.status.code, None);
}
#[test]
fn launch529_unknown_observation_preserves_optional_status() {
    use super::observation::Status;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        Status::capture(None),
        Status {
            present: false,
            code: None,
            signal: None
        }
    );
    let exited = std::process::ExitStatus::from_raw(7 << 8);
    assert_eq!(
        Status::capture(Some(&exited)),
        Status {
            present: true,
            code: Some(7),
            signal: None
        }
    );
    let signaled = std::process::ExitStatus::from_raw(nix::libc::SIGTERM);
    assert_eq!(
        Status::capture(Some(&signaled)),
        Status {
            present: true,
            code: None,
            signal: Some(nix::libc::SIGTERM)
        }
    );
}
#[test]
fn launch529_unknown_observation_is_bounded_and_non_authoritative() {
    use super::observation::{self as d, Event, Origin, Report, Subcase};
    use local_channel::launch::{
        DebtObservation, ObservationAccess as A, ObservationEnd as E, SettlementReason,
    };
    let mut snapshot = diagnostic_snapshot(None);
    snapshot.debt_sample = d::DebtSample::Captured;
    snapshot.debt = Some(DebtObservation {
        local: A::Available,
        live: Some(u32::MAX),
        uncertain: Some(true),
        settled: false,
        ends: A::Available,
        own: Some(E::Uncertain),
        peer: Some(E::Uncertain),
        budget: A::Available,
        budget_present: true,
        budget_nonzero: Some(true),
        reason: Some(SettlementReason::Inconsistent),
    });
    let report = Report {
        first: Some(Event {
            origin: Origin::RemoteSettlement,
            errno: Some(i32::MIN),
            snapshot,
        }),
        rejection: Some(d::Rejection { errno: None }),
        current: Some(snapshot),
        unavailable: None,
    };
    let saved = report;
    let rendered = d::render(Subcase::RecordReservedPrefix, &report);
    assert!(rendered.len() <= 2048);
    assert!(rendered.contains("subcase=record_reserved_prefix"));
    assert!(rendered.contains("rejection=Some(Rejection { errno: None })"));
    assert_eq!(report, saved, "observation cannot mutate custody state");
    let fallback = d::render_capped(Subcase::RecordMagic, &report, 64);
    assert!(
        fallback.len() <= 64,
        "oversize diagnostic must use fixed unavailable fallback"
    );
    assert!(fallback.contains("unavailable"));
    for reason in [
        Origin::RegistryMissing,
        Origin::CapsulePoisoned,
        Origin::CapsuleBusy,
    ] {
        let report = Report {
            first: None,
            rejection: None,
            current: None,
            unavailable: Some(reason),
        };
        assert!(d::render(Subcase::Other, &report).len() <= 2048);
    }
}

// Only setup I/O is faulted; actual peer EOF is read from the owned socket.
// The terminal/lost wait setters below remain explicit child-free models.
fn inject_setup_read(
    launches: &mut super::FrontendLaunches,
    handle: &super::LaunchHandle,
    error: std::io::Error,
) {
    launches
        .find(handle)
        .unwrap()
        .lock()
        .unwrap()
        .setup_read_fault = Some(error);
}
fn reset_model() -> (super::FrontendLaunches, super::LaunchHandle) {
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(60))
        .unwrap();
    launches.test_started(&handle);
    (launches, handle)
}
fn reset_read_receipt_orders() {
    use std::os::fd::AsRawFd;
    for eof_first in [false, true] {
        let (mut launches, handle) = reset_model();
        let setup = launches
            .find(&handle)
            .unwrap()
            .lock()
            .unwrap()
            .setup
            .as_ref()
            .unwrap()
            .fd()
            .unwrap()
            .as_raw_fd();
        for kind in [
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::WouldBlock,
        ] {
            inject_setup_read(&mut launches, &handle, std::io::Error::from(kind));
            assert_eq!(launches.poll(&handle), super::LaunchProgress::Preparing);
            let capsule = launches.find(&handle).unwrap();
            let c = capsule.lock().unwrap();
            assert!(!c.cancelled() && !c.eof && !c.unknown);
        }
        let expected_errno = if eof_first {
            Some(nix::libc::ECONNRESET)
        } else {
            None
        };
        for repeat in 0..2 {
            let error = if repeat == 0 && !eof_first {
                std::io::Error::from(std::io::ErrorKind::ConnectionReset)
            } else {
                std::io::Error::from_raw_os_error(nix::libc::ECONNRESET)
            };
            inject_setup_read(&mut launches, &handle, error);
            assert_eq!(
                launches.poll(&handle),
                super::LaunchProgress::Closing,
                "reset rejects setup without losing physical custody"
            );
            let capsule = launches.find(&handle).unwrap();
            let c = capsule.lock().unwrap();
            assert!(c.cancelled() && !c.eof && !c.unknown && !c.kill_attempted);
            assert_eq!(c.wait, super::WaitState::Pending);
            assert!(c.status.is_none() && c.first_unknown.is_none());
            assert_eq!(
                c.first_rejection,
                Some(super::observation::Rejection {
                    errno: expected_errno
                })
            );
            assert_eq!(c.setup.as_ref().unwrap().fd().unwrap().as_raw_fd(), setup);
            assert!(c.remote.is_some() && c.setup_child.is_some());
        }
        // Missing optional diagnostic data cannot change physical settlement.
        if !eof_first {
            launches
                .find(&handle)
                .unwrap()
                .lock()
                .unwrap()
                .first_rejection = None;
        }
        // With the real peer still open the next actual read is WouldBlock.
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Closing);
        assert_eq!(launches.in_use(), 1);
        assert_eq!(launches.budget.in_use(), 1);
        assert!(matches!(
            launches.prepare(config(), Instant::now() + Duration::from_secs(60)),
            Err(local_channel::AdmissionError::Capacity)
        ));
        assert!(!launches.test_publish(&handle));
        if eof_first {
            launches.test_eof(&handle);
        } else {
            launches.test_wait(&handle, false);
        }
        assert_eq!(
            launches.poll(&handle),
            super::LaunchProgress::Closing,
            "one physical receipt is insufficient"
        );
        {
            let capsule = launches.find(&handle).unwrap();
            let c = capsule.lock().unwrap();
            assert_eq!(c.eof, eof_first);
            assert_eq!(
                c.wait,
                if eof_first {
                    super::WaitState::Pending
                } else {
                    super::WaitState::Terminal
                }
            );
            assert!(
                c.status.is_none(),
                "modeled wait is not an actual ExitStatus"
            );
        }
        assert_eq!(launches.in_use(), 1);
        assert_eq!(launches.budget.in_use(), 1);
        if eof_first {
            launches.test_wait(&handle, false);
        } else {
            launches.test_eof(&handle);
        }
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
        assert_eq!(launches.in_use(), 0);
        assert_eq!(launches.budget.in_use(), 0);
    }
}
fn reset_uncertainties_stay_charged() {
    for failure in [
        "lost-wait",
        "uncertain-close",
        "preexisting-unknown",
        "other-read",
    ] {
        let (mut launches, handle) = reset_model();
        if failure == "preexisting-unknown" {
            launches.test_wait(&handle, true);
        }
        inject_setup_read(
            &mut launches,
            &handle,
            std::io::Error::from_raw_os_error(nix::libc::ECONNRESET),
        );
        assert_eq!(
            launches.poll(&handle),
            if failure == "preexisting-unknown" {
                super::LaunchProgress::Unknown
            } else {
                super::LaunchProgress::Closing
            }
        );
        if failure == "lost-wait" {
            launches.test_wait(&handle, true);
        }
        if failure == "uncertain-close" {
            launches.test_wait(&handle, false);
            launches.test_uncertain_close(&handle);
        }
        if failure == "other-read" {
            inject_setup_read(
                &mut launches,
                &handle,
                std::io::Error::from(std::io::ErrorKind::Other),
            );
            assert_eq!(launches.poll(&handle), super::LaunchProgress::Unknown);
        }
        let report = launches.observation(&handle);
        assert!(
            report.rejection.is_some(),
            "logical rejection is separate from first physical uncertainty"
        );
        let original = report.first;
        if failure != "uncertain-close" {
            assert!(original.is_some());
        }
        launches.test_eof(&handle); // closes real owned setup peer copies
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Unknown);
        let physical = launches.observation(&handle).first.unwrap();
        if let Some(original) = original {
            assert_eq!(physical, original);
        }
        inject_setup_read(
            &mut launches,
            &handle,
            std::io::Error::from_raw_os_error(nix::libc::ECONNRESET),
        );
        // EOF may already suppress further reads; neither case can clear Unknown.
        assert_eq!(launches.poll(&handle), super::LaunchProgress::Unknown);
        assert_eq!(launches.observation(&handle).first, Some(physical));
        assert_eq!(launches.in_use(), 1);
        assert_eq!(launches.budget.in_use(), 1);
        let capsule = launches.find(&handle).unwrap();
        let c = capsule.lock().unwrap();
        assert!(c.eof && c.unknown && !c.kill_attempted && c.status.is_none());
    }
}

#[test]
fn launch529_prepare_observation_records_real_socket_refusal() {
    use local_channel::prepare_observation::{Check, Class, Event, Observer, Site};
    let file: std::os::fd::OwnedFd = tempfile::tempfile().unwrap().into();
    let mut observed = Observer::default();
    assert_eq!(
        local_channel::validate_socket_observed(
            &file,
            config(),
            Site::ProvisionFrontend,
            &mut observed,
        ),
        Err(local_channel::AdmissionError::Refused)
    );
    assert_eq!(
        observed.first,
        Some(Event {
            site: Site::ProvisionFrontend,
            check: Check::GetsocknameCall,
            class: Class::Syscall,
            errno: Some(nix::libc::ENOTSOCK),
        }),
        "the actual failing socket call must carry its own errno"
    );
    let mut absent = Observer {
        suppressed: true,
        ..Default::default()
    };
    assert_eq!(
        local_channel::validate_socket_observed(
            &file,
            config(),
            Site::ProvisionFrontend,
            &mut absent,
        ),
        Err(local_channel::AdmissionError::Refused)
    );
    assert!(absent.first.is_none());
    // The validator borrowed the real object and acquired no additional ownership.
    let file = std::fs::File::from(file);
    assert!(file.metadata().unwrap().is_file());
}

#[test]
fn launch529_prepare_observation_is_first_and_invocation_owned() {
    use local_channel::prepare_observation::{Observer, Site};
    let file: std::os::fd::OwnedFd = tempfile::tempfile().unwrap().into();
    let mut a = Observer::default();
    let mut b = Observer::default();
    for site in [Site::ProvisionFrontend, Site::ProvisionHost] {
        assert_eq!(
            local_channel::validate_socket_observed(&file, config(), site, &mut a),
            Err(local_channel::AdmissionError::Refused)
        );
        assert_eq!(a.first.unwrap().site, Site::ProvisionFrontend);
        assert!(
            b.first.is_none(),
            "a distinct invocation has no shared cache"
        );
    }
    assert_eq!(
        local_channel::validate_socket_observed(&file, config(), Site::SetupChild, &mut b),
        Err(local_channel::AdmissionError::Refused)
    );
    assert_eq!(b.first.unwrap().site, Site::SetupChild);
    assert_eq!(a.first.unwrap().site, Site::ProvisionFrontend);
    a.begin();
    assert!(a.first.is_none());
    assert_eq!(
        local_channel::validate_socket_observed(&file, config(), Site::SetupParent, &mut a),
        Err(local_channel::AdmissionError::Refused)
    );
    assert_eq!(a.first.unwrap().site, Site::SetupParent);
    assert_eq!(b.first.unwrap().site, Site::SetupChild);
}

#[test]
fn launch529_prepare_observation_is_closed_and_bounded() {
    use local_channel::prepare_observation::{Check, Class, Event, Observer, Site};
    for errno in [None, Some(0), Some(i32::MIN), Some(i32::MAX)] {
        for error in [
            local_channel::AdmissionError::InvalidConfig,
            local_channel::AdmissionError::Capacity,
            local_channel::AdmissionError::Unavailable,
            local_channel::AdmissionError::Refused,
            local_channel::AdmissionError::Deadline,
        ] {
            let mut observer = Observer::default();
            observer.record(Event {
                site: Site::ProvisionFrontend,
                check: Check::GetsocknameCall,
                class: Class::SyntheticSyscall,
                errno,
            });
            let before = observer.first;
            let line = observer.render(error);
            assert!(line.len() <= 1024);
            assert!(line.contains(&format!("errno={errno:?}")));
            assert!(line.contains(&format!("error={error:?}")));
            assert_eq!(observer.first, before);
            for forbidden in ["uid=", "gid=", "pid=", "fd=", "path=", "nonce=", "payload="] {
                assert!(!line.contains(forbidden));
            }
        }
    }
    let missing = Observer::default().render(local_channel::AdmissionError::Refused);
    assert!(missing.contains("check=MissingObservation"));
    assert!(missing.contains("errno=None"));
}

// Only one actual socket-validation result is faulted. No OS child is created.
fn prepare_observation_sites() {
    use local_channel::prepare_observation::{Check, Class, FaultKind, Site};
    for site in [
        Site::ProvisionFrontend,
        Site::ProvisionHost,
        Site::SplitFrontend,
        Site::SetupParent,
        Site::SetupChild,
    ] {
        for kind in [FaultKind::Syscall, FaultKind::Predicate] {
            for suppressed in [false, true] {
                let mut launches = super::FrontendLaunches::new(1).unwrap();
                launches.prepare_observer.fault = Some((site, kind));
                launches.prepare_observer.suppressed = suppressed;
                let result = launches.prepare(config(), Instant::now() + Duration::from_secs(60));
                let error = match result {
                    Err(error) => error,
                    Ok(handle) => {
                        launches.cancel(&handle);
                        assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
                        panic!("faulted validation must preserve the refusal result");
                    }
                };
                assert_eq!(error, local_channel::AdmissionError::Refused);
                assert_eq!(launches.in_use(), 0);
                assert_eq!(launches.budget.in_use(), 0);
                assert!(launches.prepare_observer.fault.is_none());
                if suppressed {
                    assert!(launches.prepare_observer.first.is_none());
                } else {
                    let event = launches.prepare_observer.first.unwrap();
                    assert_eq!(event.site, site);
                    match kind {
                        FaultKind::Syscall => {
                            assert_eq!(event.check, Check::GetsocknameCall);
                            assert_eq!(event.class, Class::SyntheticSyscall);
                            assert_eq!(event.errno, Some(123));
                        }
                        FaultKind::Predicate => {
                            assert_eq!(event.check, Check::UnixFamily);
                            assert_eq!(event.class, Class::SyntheticPredicate);
                            assert_eq!(event.errno, None);
                        }
                    }
                }
                let handle = launches
                    .prepare(config(), Instant::now() + Duration::from_secs(60))
                    .unwrap();
                assert!(
                    launches.prepare_observer.first.is_none(),
                    "success resets detail"
                );
                assert_eq!(launches.in_use(), 1);
                assert_eq!(launches.budget.in_use(), 1);
                launches.cancel(&handle);
                assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
                assert_eq!(launches.budget.in_use(), 0);
            }
        }
    }
    let mut launches = super::FrontendLaunches::new(1).unwrap();
    launches.prepare_observer.fault = Some((Site::ProvisionFrontend, FaultKind::Syscall));
    assert!(matches!(
        launches.prepare(config(), Instant::now()),
        Err(local_channel::AdmissionError::Deadline)
    ));
    assert!(launches.prepare_observer.first.is_none());
    assert!(
        launches.prepare_observer.fault.is_none(),
        "unused faults end with the invocation"
    );
    let handle = launches
        .prepare(config(), Instant::now() + Duration::from_secs(60))
        .unwrap();
    assert!(launches.prepare_observer.first.is_none());
    launches.cancel(&handle);
    assert_eq!(launches.poll(&handle), super::LaunchProgress::Settled);
}

// A child-free model of Command::spawn returning Err, not an actual exec/wait proof.
// The setup peer copies and all other local descriptors are still genuinely owned.
fn shutdown_model(exec_refused: bool) -> (super::FrontendLaunches, super::LaunchHandle) {
    let (launches, handle) = reset_model();
    if exec_refused {
        let capsule = launches.find(&handle).unwrap();
        let mut c = capsule.lock().unwrap();
        c.export = super::ExportDisposition::ExecRefused;
        c.wait = super::WaitState::NotCreated;
        c.modeled_child = false;
        c.close_child_copies();
    }
    (launches, handle)
}
fn inject_shutdown(launches: &super::FrontendLaunches, handle: &super::LaunchHandle, errno: i32) {
    launches
        .find(handle)
        .unwrap()
        .lock()
        .unwrap()
        .setup_shutdown_fault = Some(std::io::Error::from_raw_os_error(errno));
}
fn shutdown_disconnection_receipt_orders() {
    use super::{ExportDisposition, LaunchProgress, WaitState};
    use std::os::fd::AsRawFd;
    for extra_copy in [false, true] {
        let (mut launches, handle) = shutdown_model(true);
        let capsule = launches.find(&handle).unwrap();
        let (deadline, setup, remote, extra) = {
            let c = capsule.lock().unwrap();
            (
                c.deadline.local(),
                c.setup.as_ref().unwrap().fd().unwrap().as_raw_fd(),
                std::ptr::from_ref(c.remote.as_ref().unwrap()),
                extra_copy.then(|| c.setup.as_ref().unwrap().duplicate().unwrap()),
            )
        };
        inject_shutdown(&launches, &handle, nix::libc::ENOTCONN);
        {
            let mut c = capsule.lock().unwrap();
            c.retire();
            c.interrupt_setup_read = true;
            assert_eq!(
                c.poll(),
                LaunchProgress::Closing,
                "disconnection is not lost custody"
            );
            assert!(c.cancelled() && !c.eof && !c.unknown && !c.kill_attempted);
            assert_eq!(c.export, ExportDisposition::ExecRefused);
            assert_eq!(c.wait, WaitState::NotCreated);
            assert!(c.child.is_none() && c.status.is_none() && c.first_unknown.is_none());
            assert_eq!(c.setup.as_ref().unwrap().fd().unwrap().as_raw_fd(), setup);
            assert_eq!(std::ptr::from_ref(c.remote.as_ref().unwrap()), remote);
            assert_eq!(c.setup_shutdown_calls, 1);
            assert!(c.write_shutdown && c.setup_shutdown_fault.is_none());
            c.interrupt_setup_read = true;
        }
        assert_eq!(launches.in_use(), 1);
        assert_eq!(launches.budget.in_use(), 1);
        assert_eq!(launches.poll(&handle), LaunchProgress::Closing);
        {
            let mut c = capsule.lock().unwrap();
            assert!(!c.eof && c.setup.is_some() && c.remote.is_some());
            assert_eq!(c.deadline.local(), deadline);
            c.retire();
            assert_eq!(
                c.setup_shutdown_calls, 1,
                "retirement never retries shutdown"
            );
        }
        assert_eq!(
            launches.budget.in_use(),
            1,
            "interruption supplies no EOF or credit"
        );
        let progress = launches.poll(&handle); // genuine read of EOF after actual peer closes
        assert_eq!(
            progress,
            if extra_copy {
                LaunchProgress::Closing
            } else {
                LaunchProgress::Settled
            }
        );
        {
            let c = capsule.lock().unwrap();
            assert!(c.eof && c.status.is_none() && !c.unknown && c.child.is_none());
            assert_eq!(c.wait, WaitState::NotCreated);
            assert_eq!(c.deadline.local(), deadline);
            assert_eq!(c.setup_shutdown_calls, 1);
        }
        if extra_copy {
            assert_eq!(
                launches.budget.in_use(),
                1,
                "a tracked local duplicate retains debt after EOF"
            );
            assert!(matches!(
                launches.prepare(config(), Instant::now() + Duration::from_secs(60)),
                Err(local_channel::AdmissionError::Capacity)
            ));
        }
        drop(extra); // actual known close, not a ledger edit
        assert_eq!(launches.poll(&handle), LaunchProgress::Settled);
        assert_eq!(launches.in_use(), 0);
        assert_eq!(launches.budget.in_use(), 0);
        assert!(
            !launches.test_publish(&handle),
            "retired launch cannot become admission"
        );
        let next = launches
            .prepare(config(), Instant::now() + Duration::from_secs(60))
            .unwrap();
        launches.cancel(&next);
        assert_eq!(launches.poll(&next), LaunchProgress::Settled);
    }
    for eof_first in [false, true] {
        let (mut launches, handle) = shutdown_model(false);
        let capsule = launches.find(&handle).unwrap();
        inject_shutdown(&launches, &handle, nix::libc::ENOTCONN);
        capsule.lock().unwrap().retire();
        assert_eq!(launches.poll(&handle), LaunchProgress::Closing);
        if eof_first {
            launches.test_eof(&handle);
        } else {
            launches.test_wait(&handle, false);
        }
        assert_eq!(
            launches.poll(&handle),
            LaunchProgress::Closing,
            "one receipt after disconnection never settles"
        );
        {
            let c = capsule.lock().unwrap();
            assert_eq!(c.eof, eof_first);
            assert_eq!(
                c.wait,
                if eof_first {
                    WaitState::Pending
                } else {
                    WaitState::Terminal
                }
            );
            assert!(
                c.child.is_none() && c.status.is_none(),
                "terminal wait is explicitly modeled"
            );
            assert_eq!(c.setup_shutdown_calls, 1);
        }
        assert_eq!(launches.budget.in_use(), 1);
        if eof_first {
            launches.test_wait(&handle, false);
        } else {
            launches.test_eof(&handle);
        }
        assert_eq!(launches.poll(&handle), LaunchProgress::Settled);
        assert_eq!(launches.budget.in_use(), 0);
    }
    // Default seam behavior performs the real SHUT_WR while its real peer remains open.
    let (mut launches, handle) = shutdown_model(false);
    let capsule = launches.find(&handle).unwrap();
    capsule.lock().unwrap().retire();
    assert_eq!(launches.poll(&handle), LaunchProgress::Closing);
    {
        let c = capsule.lock().unwrap();
        assert!(!c.eof && !c.unknown && c.first_unknown.is_none());
        assert_eq!(c.setup_shutdown_calls, 1);
    }
    launches.test_wait(&handle, false);
    launches.test_eof(&handle);
    assert_eq!(launches.poll(&handle), LaunchProgress::Settled);
    assert_eq!(launches.budget.in_use(), 0);
}
fn shutdown_uncertainties_stay_charged() {
    use super::{observation::Origin, LaunchProgress, WaitState};
    use std::os::fd::AsRawFd;
    for errno in [
        nix::libc::EBADF,
        nix::libc::ENOTSOCK,
        nix::libc::EINVAL,
        nix::libc::EINTR,
        nix::libc::EIO,
    ] {
        let (mut launches, handle) = shutdown_model(true);
        let capsule = launches.find(&handle).unwrap();
        inject_shutdown(&launches, &handle, errno);
        let deadline = capsule.lock().unwrap().deadline.local();
        let first = {
            let mut c = capsule.lock().unwrap();
            c.retire();
            c.interrupt_setup_read = true;
            assert_eq!(c.poll(), LaunchProgress::Unknown);
            let first = c.first_unknown.unwrap();
            assert_eq!(first.origin, Origin::SetupShutdown);
            assert_eq!(
                first.errno,
                Some(errno),
                "synthetic shutdown result reaches the real Unknown branch"
            );
            let fd = c.setup.as_ref().unwrap().fd().unwrap().as_raw_fd();
            assert!(
                unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0,
                "injected EBADF never forges or destroys FD ownership"
            );
            c.setup_shutdown_fault = Some(std::io::Error::from_raw_os_error(nix::libc::ENOTCONN));
            c.retire();
            assert_eq!(c.setup_shutdown_calls, 1);
            assert!(
                c.setup_shutdown_fault.is_some(),
                "one-shot guard leaves later fault unused"
            );
            assert_eq!(c.first_unknown, Some(first));
            first
        };
        assert_eq!(launches.poll(&handle), LaunchProgress::Unknown);
        let c = capsule.lock().unwrap();
        assert!(c.eof && c.unknown && !c.kill_attempted && c.setup.is_some() && c.remote.is_some());
        assert_eq!(c.first_unknown, Some(first));
        assert_eq!(c.deadline.local(), deadline);
        drop(c);
        assert_eq!(launches.budget.in_use(), 1);
    }
    for lost_before in [false, true] {
        let (mut launches, handle) = shutdown_model(false);
        let capsule = launches.find(&handle).unwrap();
        if lost_before {
            launches.test_wait(&handle, true);
        }
        inject_shutdown(&launches, &handle, nix::libc::ENOTCONN);
        capsule.lock().unwrap().retire();
        if !lost_before {
            launches.test_wait(&handle, true);
        }
        let first = launches.observation(&handle).first.unwrap();
        assert_eq!(first.origin, Origin::ModeledLostWait);
        launches.test_eof(&handle); // actual setup peer closes, never a direct EOF assignment
        assert_eq!(launches.poll(&handle), LaunchProgress::Unknown);
        {
            let mut c = capsule.lock().unwrap();
            c.kill_owned();
            assert!(c.eof && c.unknown && !c.kill_attempted && c.status.is_none());
            assert_eq!(c.wait, WaitState::Unknown);
            assert_eq!(c.first_unknown, Some(first));
            assert_eq!(c.setup_shutdown_calls, 1);
        }
        assert_eq!(launches.budget.in_use(), 1);
    }
    for close_before in [false, true] {
        let (mut launches, handle) = shutdown_model(true);
        let capsule = launches.find(&handle).unwrap();
        let mut extra = Some(
            capsule
                .lock()
                .unwrap()
                .setup
                .as_ref()
                .unwrap()
                .duplicate()
                .unwrap(),
        );
        if close_before {
            extra.as_mut().unwrap().test_uncertain_close();
            drop(extra.take());
        }
        inject_shutdown(&launches, &handle, nix::libc::ENOTCONN);
        capsule.lock().unwrap().retire();
        if !close_before {
            extra.as_mut().unwrap().test_uncertain_close();
            drop(extra.take());
        }
        assert_eq!(launches.poll(&handle), LaunchProgress::Unknown);
        let first = launches.observation(&handle).first.unwrap();
        assert_eq!(first.origin, Origin::RemoteSettlement);
        assert!(first.snapshot.debt.unwrap().uncertain.unwrap());
        launches.cancel(&handle);
        assert_eq!(launches.poll(&handle), LaunchProgress::Unknown);
        assert_eq!(launches.observation(&handle).first, Some(first));
        assert_eq!(launches.budget.in_use(), 1);
        let c = capsule.lock().unwrap();
        assert!(c.eof && c.unknown && !c.kill_attempted && c.status.is_none());
        assert_eq!(c.setup_shutdown_calls, 1);
    }
}
