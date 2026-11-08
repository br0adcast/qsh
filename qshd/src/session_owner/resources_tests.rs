use super::authorization_contract::*;
use super::resource_contract::*;
use super::resources::*;
use std::sync::{Arc, Mutex};
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::*;
fn limits() -> ResourceLimits {
    let bytes = ByteLimits {
        channel_bytes: 64,
        session_bytes: 64,
        account_bytes: 64,
        global_bytes: 128,
    };
    ResourceLimits {
        max_reservations: 8,
        screen: ScreenLimits {
            global_cells: 1,
            account_cells: 1,
            global_rows: 1,
            account_rows: 1,
            global_models: 1,
            account_models: 1,
        },
        snapshot_transfer: bytes,
        control_queue: bytes,
    }
}
#[test]
fn resources_two_owners_share_real_alias_limit_and_exact_cleanup() {
    let mut ledger = ResourceLedger::new(LedgerInstance::new([31; 16]).unwrap(), limits()).unwrap();
    let p = AuthenticatedPrincipalRef::new([1; 16]).unwrap();
    let alias = AuthenticatedPrincipalRef::new([2; 16]).unwrap();
    let first = ledger.register_fresh_principal(p, 1000).unwrap();
    let second = ledger.register_fresh_principal(alias, 1000).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    let a = OwnerResourceClient::new(ledger.clone(), first);
    let b = OwnerResourceClient::new(ledger.clone(), second);
    let reservation = |id, principal, session| Reservation {
        id: ReservationId::new(id).unwrap(),
        principal,
        locator: SessionLocator {
            session: RetainedSessionId::new([session; 16]).unwrap(),
            owner: OwnerInstance::new([session; 16]).unwrap(),
        },
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 40,
        screen_charge: None,
    };
    let one = reservation(1, p, 1);
    let two = reservation(2, alias, 2);
    let cleanup = RequestId::new(7).unwrap();
    let admitted = a.reserve(one, cleanup).unwrap();
    assert!(b.reserve(two, cleanup).is_err());
    let mut receipt = ReservationReceipt {
        id: cleanup,
        reservation: one.id,
        locator: one.locator,
        channel: one.channel,
    };
    receipt.id = RequestId::new(8).unwrap();
    assert!(a.release(&admitted, receipt).is_err());
    assert_eq!(ledger.lock().unwrap().reservations(), 1);
    receipt.id = cleanup;
    a.release(&admitted, receipt).unwrap();
    assert!(b.reserve(two, cleanup).is_ok());
}

#[test]
fn resources_foreign_client_cannot_spend_a_matching_cleanup_token() {
    let mut ledger = ResourceLedger::new(LedgerInstance::new([32; 16]).unwrap(), limits()).unwrap();
    let p = AuthenticatedPrincipalRef::new([3; 16]).unwrap();
    let q = AuthenticatedPrincipalRef::new([4; 16]).unwrap();
    let reg_p = ledger.register_fresh_principal(p, 1000).unwrap();
    let reg_q = ledger.register_fresh_principal(q, 1000).unwrap();
    let shared = Arc::new(Mutex::new(ledger));
    let a = OwnerResourceClient::new(shared.clone(), reg_p);
    let b = OwnerResourceClient::new(shared.clone(), reg_q);
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: p,
        locator: SessionLocator {
            session: RetainedSessionId::new([3; 16]).unwrap(),
            owner: OwnerInstance::new([3; 16]).unwrap(),
        },
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 40,
        screen_charge: None,
    };
    let cleanup = RequestId::new(1).unwrap();
    let token = a.reserve(r, cleanup).unwrap();
    let receipt = ReservationReceipt {
        id: cleanup,
        reservation: r.id,
        locator: r.locator,
        channel: r.channel,
    };
    assert!(
        b.release(&token, receipt).is_err(),
        "another host registration spent the admitted token"
    );
    assert_eq!(shared.lock().unwrap().reservations(), 1);
    a.release(&token, receipt).unwrap();
}

#[test]
fn resources_rebuilt_host_rejects_old_token_with_reused_public_receipt() {
    let p = AuthenticatedPrincipalRef::new([5; 16]).unwrap();
    let make = |scope| {
        let mut ledger =
            ResourceLedger::new(LedgerInstance::new([scope; 16]).unwrap(), limits()).unwrap();
        let registration = ledger.register_fresh_principal(p, 1000).unwrap();
        let shared = Arc::new(Mutex::new(ledger));
        (
            OwnerResourceClient::new(shared.clone(), registration),
            shared,
        )
    };
    let (old, _) = make(41);
    let (fresh, shared) = make(42);
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: p,
        locator: SessionLocator {
            session: RetainedSessionId::new([5; 16]).unwrap(),
            owner: OwnerInstance::new([5; 16]).unwrap(),
        },
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 40,
        screen_charge: None,
    };
    let cleanup = RequestId::new(1).unwrap();
    let stale = old.reserve(r, cleanup).unwrap();
    let live = fresh.reserve(r, cleanup).unwrap();
    let receipt = ReservationReceipt {
        id: cleanup,
        reservation: r.id,
        locator: r.locator,
        channel: r.channel,
    };
    assert!(fresh.release(&stale, receipt).is_err());
    assert_eq!(shared.lock().unwrap().reservations(), 1);
    fresh.release(&live, receipt).unwrap();
    old.release(&stale, receipt).unwrap();
}
