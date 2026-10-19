use super::*;

fn endpoint(n: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40000 + n as u16))
}

fn catalog(n: usize) -> Vec<RecoveryEndpoint> {
    (0..n)
        .map(|address| RecoveryEndpoint {
            address,
            endpoint: endpoint(address),
        })
        .collect()
}

#[test]
fn all_catalog_members_get_a_bounded_turn_without_waiting_for_silence() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(now, catalog(19));
    let mut sent = Vec::new();
    for (millis, count) in [(0, 8), (50, 8), (100, 3)] {
        let at = now + Duration::from_millis(millis);
        let work = schedule.poll(at);
        assert_eq!(work.len(), count);
        for dispatch in work {
            sent.push(dispatch.endpoint);
            schedule.sent(at, dispatch.endpoint, true);
        }
        assert!(
            schedule.poll(at).is_empty(),
            "polling cannot reset the shared budget"
        );
    }
    sent.sort();
    assert_eq!(sent, (0..19).map(endpoint).collect::<Vec<_>>());
}

#[test]
fn aliases_share_a_physical_send_but_retain_every_logical_member() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(
        now,
        vec![
            RecoveryEndpoint {
                address: 7,
                endpoint: endpoint(0),
            },
            RecoveryEndpoint {
                address: 11,
                endpoint: endpoint(0),
            },
            RecoveryEndpoint {
                address: 7,
                endpoint: endpoint(0),
            },
            RecoveryEndpoint {
                address: 12,
                endpoint: endpoint(1),
            },
        ],
    );
    assert_eq!(schedule.poll(now).len(), 2);
    assert_eq!(schedule.aliases(endpoint(0)), &[7, 11]);
    assert_eq!(schedule.aliases(endpoint(1)), &[12]);
}

#[test]
fn queued_work_has_no_check_deadline_or_eligible_response_before_actual_dispatch() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(now, catalog(2));
    assert_eq!(schedule.poll(now).len(), 2);
    assert_eq!(schedule.first_checked(endpoint(0)), None);
    assert!(!schedule.can_select(endpoint(0)));
    assert!(!schedule.on_cookie(now, endpoint(0), [1; COOKIE_LEN]));
    let later = now + Duration::from_secs(20);
    schedule.sent(later, endpoint(0), true);
    schedule.sent(later, endpoint(1), false);
    assert_eq!(schedule.first_checked(endpoint(0)), Some(later));
    assert_eq!(schedule.first_checked(endpoint(1)), Some(later));
    assert!(schedule.can_select(endpoint(0)));
    assert!(!schedule.can_select(endpoint(1)));
    assert!(!schedule.can_select(endpoint(99)));
}

#[test]
fn cookie_retries_are_endpoint_local_and_keep_plain_turns_and_original_deadline() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(now, catalog(2));
    for dispatch in schedule.poll(now) {
        schedule.sent(now, dispatch.endpoint, true);
    }
    let cookie_at = now + Duration::from_millis(1);
    assert!(schedule.on_cookie(cookie_at, endpoint(0), [7; COOKIE_LEN]));
    let immediate = schedule.poll(cookie_at);
    assert_eq!(immediate.len(), 1);
    assert_eq!(immediate[0].endpoint, endpoint(0));
    assert_eq!(immediate[0].cookie, Some([7; COOKIE_LEN]));
    schedule.sent(cookie_at, endpoint(0), true);
    let next = now + Duration::from_millis(501);
    let work = schedule.poll(next);
    assert_eq!(work.len(), 2);
    for dispatch in work {
        assert_eq!(
            dispatch.cookie,
            (dispatch.endpoint == endpoint(0)).then_some([7; COOKIE_LEN])
        );
        schedule.sent(next, dispatch.endpoint, true);
    }
    assert!(schedule.on_cookie(next, endpoint(0), [8; COOKIE_LEN]));
    assert!(
        schedule.poll(next).is_empty(),
        "refreshing a cookie is not another immediate turn"
    );
    let work = schedule.poll(next + Duration::from_millis(500));
    assert_eq!(work.len(), 2);
    assert!(work.iter().all(|dispatch| dispatch.cookie.is_none()));
    assert_eq!(schedule.first_checked(endpoint(0)), Some(now));
}

#[test]
fn immediate_cookies_share_the_turn_budget_and_cannot_starve_unsent_members() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(now, catalog(16));
    for dispatch in schedule.poll(now) {
        schedule.sent(now, dispatch.endpoint, true);
        assert!(schedule.on_cookie(now, dispatch.endpoint, [1; COOKIE_LEN]));
    }
    assert!(schedule.poll(now).is_empty());
    let work = schedule.poll(now + Duration::from_millis(50));
    assert_eq!(
        work.iter()
            .map(|dispatch| dispatch.endpoint)
            .collect::<Vec<_>>(),
        (8..16).map(endpoint).collect::<Vec<_>>()
    );
    assert!(schedule.poll(now + Duration::from_millis(50)).is_empty());
}

#[test]
fn selection_is_single_and_completed_members_stop_sending() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(now, catalog(2));
    for dispatch in schedule.poll(now) {
        schedule.sent(now, dispatch.endpoint, true);
    }
    assert!(schedule.select(endpoint(1)));
    assert_eq!(schedule.selected(), Some(endpoint(1)));
    assert!(!schedule.can_select(endpoint(0)));
    assert!(!schedule.select(endpoint(0)));
    schedule.finish(endpoint(0));
    let work = schedule.poll(now + Duration::from_millis(500));
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].endpoint, endpoint(1));
    schedule.retire();
    assert!(schedule.poll(now + Duration::from_secs(100)).is_empty());
    assert_eq!(schedule.next_deadline(), None);
}

#[test]
fn cookie_between_reservation_and_send_does_not_relabel_plain_work() {
    let now = Instant::now();
    let mut schedule = RecoveryHandshake::new(now, catalog(1));
    schedule.poll(now);
    schedule.sent(now, endpoint(0), true);
    let retry_at = now + HANDSHAKE_RETRY_INTERVAL;
    assert_eq!(schedule.poll(retry_at)[0].cookie, None);
    assert!(schedule.on_cookie(retry_at, endpoint(0), [9; COOKIE_LEN]));
    schedule.sent(retry_at, endpoint(0), true);
    assert_eq!(schedule.poll(retry_at)[0].cookie, Some([9; COOKIE_LEN]));
    schedule.sent(retry_at, endpoint(0), true);
    assert_eq!(
        schedule.poll(retry_at + HANDSHAKE_RETRY_INTERVAL)[0].cookie,
        Some([9; COOKIE_LEN]),
        "first regular turn after the immediate retry carries the cookie"
    );
}
