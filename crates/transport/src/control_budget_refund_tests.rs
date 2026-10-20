use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

struct RefundWake {
    global: GlobalBudget,
    session: Arc<Mutex<SessionState>>,
    wakes: AtomicUsize,
    locks_released: AtomicBool,
}
impl RefundWake {
    fn new(global: &GlobalBudget, session: &SessionBudget) -> Arc<Self> {
        Arc::new(Self {
            global: global.clone(),
            session: session.state.clone(),
            wakes: AtomicUsize::new(0),
            locks_released: AtomicBool::new(false),
        })
    }
}
impl Wake for RefundWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        self.locks_released.store(
            self.global.0.try_lock().is_ok() && self.session.try_lock().is_ok(),
            Ordering::SeqCst,
        );
    }
}

#[test]
fn capacity_refund_response_wakes_all_registered_admissions_after_unlock() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let response = session.reserve(Response::Ordinary(5)).unwrap();
    let wake = RefundWake::new(&global, &session);
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut first = Box::pin(global.changed());
    let mut second = Box::pin(global.changed());
    first.as_mut().enable();
    second.as_mut().enable();
    assert_eq!(first.as_mut().poll(&mut context), Poll::Pending);
    assert_eq!(second.as_mut().poll(&mut context), Poll::Pending);
    drop(response);
    assert_eq!(
        wake.wakes.load(Ordering::SeqCst),
        2,
        "every paused runner can retry"
    );
    assert!(
        wake.locks_released.load(Ordering::SeqCst),
        "refund wake reentered locked accounting"
    );
    assert_eq!(first.as_mut().poll(&mut context), Poll::Ready(()));
    assert_eq!(second.as_mut().poll(&mut context), Poll::Ready(()));
    let mut later = Box::pin(global.changed());
    later.as_mut().enable();
    assert_eq!(
        later.as_mut().poll(&mut context),
        Poll::Pending,
        "old refund is not stored as perpetual ready work"
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_refund_retired_job_wakes_only_after_final_worker_custody_drops() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let mut owner = crate::control_job::JobOwner::reserve(&session, Job::Update).unwrap();
    let lease = owner.take_worker().unwrap();
    let wake = RefundWake::new(&global, &session);
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut retry = Box::pin(global.changed());
    retry.as_mut().enable();
    assert_eq!(retry.as_mut().poll(&mut context), Poll::Pending);
    session.retire();
    drop(owner);
    assert_eq!(retry.as_mut().poll(&mut context), Poll::Pending);
    assert_eq!(global.retained_for_test().2, 1);
    drop(lease);
    assert_eq!(
        retry.as_mut().poll(&mut context),
        Poll::Ready(()),
        "actual final job refund wakes admission"
    );
    assert_eq!(wake.wakes.load(Ordering::SeqCst), 1);
    assert!(wake.locks_released.load(Ordering::SeqCst));
    assert_eq!(global.retained_for_test().2, 0);
    assert!(crate::control_job::JobOwner::reserve(&global.session(1), Job::Update).is_ok());
}

#[test]
fn capacity_refund_preflight_shrink_reuses_bytes_without_refunding_entry() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let mut response = session.reserve(Response::Ordinary(MAX_RECORD)).unwrap();
    assert!(matches!(
        session.reserve(Response::Ordinary(1)),
        Err(CapacityError::Session)
    ));
    let wake = RefundWake::new(&global, &session);
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut retry = Box::pin(global.changed());
    retry.as_mut().enable();
    assert_eq!(retry.as_mut().poll(&mut context), Poll::Pending);
    response.shrink_ordinary(5).unwrap();
    assert_eq!(global.retained_for_test(), (2 * 5, 1, 0));
    assert_eq!(retry.as_mut().poll(&mut context), Poll::Ready(()));
    assert!(wake.locks_released.load(Ordering::SeqCst));
    let rest = session.reserve(Response::Ordinary(MAX_RECORD - 5)).unwrap();
    assert_eq!(global.retained_for_test(), (2 * MAX_RECORD, 2, 0));
    let mut owner = response.into_owner();
    let record = owner.take_record(5).unwrap();
    drop(owner);
    drop(rest);
    assert_eq!(
        global.retained_for_test(),
        (2 * 5, 1, 0),
        "record still owns the shrunken entry"
    );
    drop(record);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_refund_shrink_rejects_growth_empty_and_mandatory_future_allowance() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let mut ordinary = session.reserve(Response::Ordinary(10)).unwrap();
    for invalid in [0, 11, usize::MAX] {
        assert_eq!(
            ordinary.shrink_ordinary(invalid),
            Err(CapacityError::InvalidSize)
        );
        assert_eq!(global.retained_for_test(), (2 * 10, 1, 0));
    }
    ordinary.shrink_ordinary(10).unwrap();
    for class in [
        Response::Open,
        Response::Update,
        Response::Snapshot,
        Response::Restart,
    ] {
        let mut mandatory = session.reserve(class).unwrap();
        let before = global.retained_for_test();
        assert_eq!(
            mandatory.shrink_ordinary(1),
            Err(CapacityError::InvalidSize)
        );
        assert_eq!(global.retained_for_test(), before);
    }
    session.retire();
    ordinary.shrink_ordinary(5).unwrap();
    assert_eq!(
        global.retained_for_test(),
        (2 * 5, 1, 0),
        "retired retained obligation may settle its excess reservation"
    );
    drop(ordinary);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
