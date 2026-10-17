use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use connect::recovery_gate::{AddressId, RecoveryEpoch};
use connect::Address;
use qsh::road_catalog::{ResolveError, RoadCatalog, RoadWork, DNS_TIMEOUT};
use transport::paths::{PathTable, MAX_PATHS, PROBE_TIMEOUT};

fn epoch() -> RecoveryEpoch {
    RecoveryEpoch {
        connection: 1,
        network: 1,
    }
}
fn addr(n: usize) -> SocketAddr {
    format!("192.0.2.{n}:60000").parse().unwrap()
}
fn configured(host: String) -> Address {
    Address {
        host,
        qsh_port: 60000,
        ssh: None,
    }
}
fn catalog(names: &[&str]) -> RoadCatalog {
    RoadCatalog::new(
        names.iter().map(|s| configured(s.to_string())).collect(),
        epoch(),
    )
}
fn request(work: &[RoadWork], id: usize) -> u64 {
    work.iter()
        .find_map(|w| match w {
            RoadWork::Resolve {
                request, address, ..
            } if *address == AddressId(id) => Some(*request),
            _ => None,
        })
        .unwrap()
}
fn published(work: &[RoadWork]) -> Option<Vec<SocketAddr>> {
    work.iter().find_map(|w| match w {
        RoadWork::Publish { paths } => Some(paths.clone()),
        _ => None,
    })
}

#[test]
fn unresolved_name_returns_without_another_login_and_keeps_its_id() {
    let mut c = catalog(&["192.0.2.1", "returning.invalid"]);
    let work = c.refresh(Duration::ZERO, addr(1), false);
    c.resolved(
        epoch(),
        request(&work, 1),
        AddressId(1),
        Err(ResolveError::NoAddress),
    );
    assert_eq!(c.address_ids(), vec![AddressId(0), AddressId(1)]);
    let work = c.refresh(Duration::from_secs(30), addr(1), false);
    c.resolved(epoch(), request(&work, 1), AddressId(1), Ok(addr(2)));
    assert!(
        published(&c.refresh(Duration::from_secs(30), addr(1), false))
            .unwrap()
            .contains(&addr(2))
    );
}

#[test]
fn stale_epoch_and_request_cannot_change_the_catalog() {
    let mut c = catalog(&["changing.invalid"]);
    let work = c.refresh(Duration::ZERO, addr(1), false);
    let old = request(&work, 0);
    let next = RecoveryEpoch {
        network: 2,
        ..epoch()
    };
    c.reset(next);
    let work = c.refresh(Duration::from_secs(1), addr(1), true);
    let current = request(&work, 0);
    c.resolved(epoch(), old, AddressId(0), Ok(addr(8)));
    c.resolved(next, old, AddressId(0), Ok(addr(7)));
    assert!(c.endpoints().is_empty());
    c.resolved(next, current, AddressId(0), Ok(addr(2)));
    assert_eq!(c.endpoints(), vec![(AddressId(0), addr(2))]);
}

#[test]
fn unfinished_dns_does_not_hold_other_addresses_and_late_completion_is_ignored() {
    let mut c = catalog(&["hung.invalid", "ready.invalid"]);
    let work = c.refresh(Duration::ZERO, addr(1), false);
    c.resolved(epoch(), request(&work, 1), AddressId(1), Ok(addr(2)));
    assert!(
        published(&c.refresh(Duration::from_secs(1), addr(1), false))
            .unwrap()
            .contains(&addr(2))
    );
    c.refresh(DNS_TIMEOUT, addr(1), false);
    c.resolved(epoch(), request(&work, 0), AddressId(0), Ok(addr(9)));
    assert_eq!(c.endpoints(), vec![(AddressId(1), addr(2))]);
}

#[test]
fn duplicate_endpoints_keep_both_logical_addresses() {
    let mut c = catalog(&["192.0.2.1", "alias.invalid"]);
    let work = c.refresh(Duration::ZERO, addr(1), false);
    c.resolved(epoch(), request(&work, 1), AddressId(1), Ok(addr(1)));
    assert_eq!(c.endpoints().len(), 2);
    assert_eq!(published(&work).unwrap(), vec![addr(1)]);
    assert!(published(&c.refresh(Duration::from_secs(1), addr(1), false)).is_none());
}

#[test]
fn ninth_and_later_addresses_get_real_probes_without_evicting_active_path() {
    let mut c = RoadCatalog::new(
        (1..=18)
            .map(|n| configured(addr(n).ip().to_string()))
            .collect(),
        epoch(),
    );
    let mut table = PathTable::new();
    let origin = Instant::now();
    let mut probed = HashSet::new();
    for second in 0..=18 {
        let now = Duration::from_secs(second);
        if let Some(paths) = published(&c.refresh(now, addr(1), true)) {
            assert!(paths.contains(&addr(1)));
            assert!(paths.len() <= MAX_PATHS);
            table.set_paths(paths);
        }
        for (path, _) in table.due(origin + now, true) {
            probed.insert(path);
        }
        for (path, sent) in table.probe_times() {
            c.probed(path, sent.duration_since(origin));
        }
    }
    assert_eq!(probed.len(), 18);
}

#[test]
fn rotation_waits_for_actual_probe_then_full_timeout_and_repetition_does_not_restart_it() {
    let mut c = RoadCatalog::new(
        (1..=9)
            .map(|n| configured(addr(n).ip().to_string()))
            .collect(),
        epoch(),
    );
    let paths = published(&c.refresh(Duration::ZERO, addr(1), true)).unwrap();
    assert!(
        published(&c.refresh(Duration::from_secs(20), addr(1), true)).is_none(),
        "publication alone is not a probe"
    );
    for path in paths {
        c.probed(path, Duration::from_secs(20));
    }
    for second in 21..23 {
        assert!(published(&c.refresh(Duration::from_secs(second), addr(1), true)).is_none());
        for path in 1..=MAX_PATHS {
            c.probed(addr(path), Duration::from_secs(second));
        }
    }
    assert!(
        published(&c.refresh(Duration::from_secs(20) + PROBE_TIMEOUT, addr(1), true))
            .unwrap()
            .contains(&addr(9))
    );
}

#[test]
fn dns_refresh_replaces_wrong_endpoint_and_urgent_edge_requests_an_immediate_retry() {
    let mut c = catalog(&["moving.invalid"]);
    let work = c.refresh(Duration::ZERO, addr(1), false);
    c.resolved(epoch(), request(&work, 0), AddressId(0), Ok(addr(8)));
    c.refresh(Duration::from_secs(1), addr(1), false);
    let work = c.refresh(Duration::from_secs(2), addr(1), true);
    c.resolved(epoch(), request(&work, 0), AddressId(0), Ok(addr(2)));
    assert_eq!(c.endpoints(), vec![(AddressId(0), addr(2))]);
    assert!(published(&c.refresh(Duration::from_secs(2), addr(1), true))
        .unwrap()
        .contains(&addr(2)));
}

#[test]
fn bounded_dns_admission_does_not_starve_names_beyond_the_first_refresh_period() {
    let mut c = RoadCatalog::new(
        (0..40)
            .map(|n| configured(format!("host-{n}.invalid")))
            .collect(),
        epoch(),
    );
    let mut attempted = HashSet::new();
    for second in 0..=50 {
        let work = c.refresh(Duration::from_secs(second), addr(1), false);
        let mut admitted = 0;
        for w in work {
            if let RoadWork::Resolve {
                request, address, ..
            } = w
            {
                if second % 5 == 0 && admitted < 4 {
                    attempted.insert(address);
                    admitted += 1;
                } else {
                    c.deferred(request, address);
                }
            }
        }
    }
    assert_eq!(
        attempted.len(),
        40,
        "names waiting on bounded capacity must precede periodic retries"
    );
}
