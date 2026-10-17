//! Refusal is a hint; authenticated alternatives and complete sweeps take priority.
use connect::recovery_gate::{AddressId, RecoveryEpoch};
use qsh::port_probe::{PortProbe, ProbeResult, RefusalWindow};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const EPOCH: RecoveryEpoch = RecoveryEpoch {
    connection: 3,
    network: 2,
};

#[test]
fn closed_loopback_port_reports_its_generation_once() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = socket.local_addr().unwrap();
    drop(socket);
    let mut probe = PortProbe::start(target, EPOCH, 9).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = loop {
        let result = probe.poll();
        if result != ProbeResult::Pending || Instant::now() >= deadline {
            break result;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        result,
        ProbeResult::Refused {
            epoch: EPOCH,
            attempt: 9,
            target
        }
    );
    assert_eq!(probe.poll(), ProbeResult::Finished);
}

#[test]
fn silence_and_an_untrusted_reply_do_not_report_refusal() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut probe = PortProbe::start(socket.local_addr().unwrap(), EPOCH, 9).unwrap();
    assert_eq!(probe.poll(), ProbeResult::Pending);
    let mut buf = [0; 256];
    let (_, from) = socket.recv_from(&mut buf).unwrap();
    socket.send_to(b"untrusted key offer", from).unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while probe.poll() == ProbeResult::Pending && Instant::now() < until {}
    assert_eq!(probe.poll(), ProbeResult::Finished);
}

#[test]
fn refusal_waits_for_every_qsh_path_and_cannot_override_a_verified_alternative() {
    let first = "127.0.0.1:60001".parse().unwrap();
    let other = "127.0.0.2:60001".parse().unwrap();
    let endpoints = [(AddressId(0), first), (AddressId(1), other)];
    let mut window = RefusalWindow::new(EPOCH, 9, Duration::ZERO, vec![AddressId(0), AddressId(1)]);
    window.observe_refusal(ProbeResult::Refused {
        epoch: EPOCH,
        attempt: 9,
        target: first,
    });
    window.probed(other, Duration::from_secs(1));
    assert!(!window.ready(Duration::from_secs(3), first, &endpoints, &[]));
    window.probed(first, Duration::from_secs(1));
    assert!(!window.ready(Duration::from_secs(3), first, &endpoints, &[]));
    assert!(!window.ready(Duration::from_secs(4), first, &endpoints, &[other]));
    assert!(window.ready(Duration::from_secs(4), first, &endpoints, &[]));
}

#[test]
fn absent_or_stale_icmp_keeps_the_original_silent_deadline() {
    let target = "127.0.0.1:60001".parse().unwrap();
    let endpoints = [(AddressId(0), target)];
    let mut window = RefusalWindow::new(EPOCH, 9, Duration::ZERO, vec![AddressId(0)]);
    window.probed(target, Duration::ZERO);
    assert!(!window.ready(Duration::from_secs(44), target, &endpoints, &[]));
    window.observe_refusal(ProbeResult::Refused {
        epoch: EPOCH,
        attempt: 8,
        target,
    });
    assert!(!window.ready(Duration::from_secs(44), target, &endpoints, &[]));
    window.observe_refusal(ProbeResult::Refused {
        epoch: RecoveryEpoch {
            network: 1,
            ..EPOCH
        },
        attempt: 9,
        target,
    });
    assert!(!window.ready(Duration::from_secs(44), target, &endpoints, &[]));
    window.observe_refusal(ProbeResult::Refused {
        epoch: EPOCH,
        attempt: 9,
        target,
    });
    assert!(!window.ready(Duration::from_secs(44), target, &endpoints, &[target]));
    assert!(window.ready(Duration::from_secs(44), target, &endpoints, &[]));
}

#[test]
fn a_candidate_beyond_the_eight_slot_table_must_get_a_qsh_probe() {
    let endpoints: Vec<_> = (0..10)
        .map(|i| {
            (
                AddressId(i),
                format!("127.0.0.1:{}", 60000 + i).parse().unwrap(),
            )
        })
        .collect();
    let mut window = RefusalWindow::new(EPOCH, 9, Duration::ZERO, (0..10).map(AddressId).collect());
    window.observe_refusal(ProbeResult::Refused {
        epoch: EPOCH,
        attempt: 9,
        target: endpoints[0].1,
    });
    for (_, endpoint) in &endpoints[..8] {
        window.probed(*endpoint, Duration::ZERO);
    }
    assert!(!window.ready(Duration::from_secs(4), endpoints[0].1, &endpoints, &[]));
    for (_, endpoint) in &endpoints[8..] {
        window.probed(*endpoint, Duration::from_secs(4));
    }
    assert!(window.ready(Duration::from_secs(7), endpoints[0].1, &endpoints, &[]));
}
