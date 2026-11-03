use super::scope::{Progress, Scope};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

fn process(pid: i32, unique: u64, sid: i32) -> Classified {
    Classified {
        identity: Identity {
            pid,
            unique,
            version: 1,
        },
        class: Class::Session(sid),
    }
}
struct Watch {
    identity: Identity,
    cookie: u64,
}
struct Model {
    before: Vec<Classified>,
    after: BTreeMap<i32, Classified>,
    raw: Vec<i32>,
    gone: BTreeSet<i32>,
    denied: BTreeSet<i32>,
    events: Vec<&'static str>,
    signals: Vec<(Identity, Signal)>,
    reaps: usize,
    leader: Result<Option<i32>, Failure>,
    reap: Result<i32, Failure>,
    event_error: bool,
    bad_event: u8,
    foreign_cookie: bool,
    token_version: Option<u32>,
    token_error: bool,
    signal_error: bool,
    exit_on_token: bool,
    bytes: Option<usize>,
}
impl Model {
    fn new(values: Vec<Classified>) -> Self {
        Self {
            raw: values.iter().map(|value| value.identity.pid).collect(),
            before: values.clone(),
            after: values.into_iter().map(|p| (p.identity.pid, p)).collect(),
            gone: BTreeSet::new(),
            denied: BTreeSet::new(),
            events: vec![],
            signals: vec![],
            reaps: 0,
            leader: Ok(Some(0)),
            reap: Ok(0),
            event_error: false,
            bad_event: 0,
            foreign_cookie: false,
            token_version: None,
            token_error: false,
            signal_error: false,
            exit_on_token: false,
            bytes: None,
        }
    }
    fn remove(&mut self, pid: i32) {
        self.before.retain(|p| p.identity.pid != pid);
        self.after.remove(&pid);
        self.raw.retain(|p| *p != pid);
    }
}
impl Ops<usize> for Model {
    type Watch = Watch;
    type Token = Identity;
    fn baseline(&mut self) -> Result<Vec<Classified>, Failure> {
        self.events.push("baseline");
        Ok(self.before.clone())
    }
    fn raw_all(&mut self, buffer: &mut [i32; CAPACITY]) -> Result<usize, Failure> {
        self.events.push("raw");
        for (slot, pid) in buffer.iter_mut().zip(&self.raw) {
            *slot = *pid;
        }
        Ok(self.bytes.unwrap_or(self.raw.len() * size_of::<i32>()))
    }
    fn confirm(&mut self, identity: Identity) -> Result<Identity, Failure> {
        self.events.push("confirm");
        self.after
            .get(&identity.pid)
            .map(|p| p.identity)
            .ok_or(Failure::Errno(3))
    }
    fn classify(&mut self, pid: i32) -> Result<Classified, Failure> {
        self.events.push("classify");
        self.after.get(&pid).copied().ok_or(Failure::Errno(3))
    }
    fn bind_exit(
        &mut self,
        value: Classified,
        cookie: u64,
    ) -> Result<Registration<Watch>, Failure> {
        self.events.push("bind");
        if self.denied.contains(&value.identity.pid) {
            return Err(Failure::Errno(3));
        }
        Ok(Registration {
            identity: value.identity,
            cookie,
            handle: Watch {
                identity: value.identity,
                cookie,
            },
        })
    }
    fn observe_exit(&mut self, watch: &mut Watch) -> Result<Option<ExitEvent>, Failure> {
        self.events.push("exit");
        if self.event_error {
            return Err(Failure::LostBinding);
        }
        Ok(self
            .gone
            .contains(&watch.identity.pid)
            .then_some(ExitEvent {
                pid: watch.identity.pid,
                cookie: watch.cookie + u64::from(self.foreign_cookie),
                process_filter: self.bad_event != 1,
                note_exit: self.bad_event != 2,
                error: self.bad_event == 3,
            }))
    }
    fn acquire_signal_token(
        &mut self,
        identity: Identity,
        sid: i32,
    ) -> Result<SignalToken<Identity>, Failure> {
        self.events.push("token");
        if self.exit_on_token {
            self.leader = Ok(Some(0));
            for value in &mut self.before {
                if value.identity.pid == identity.pid {
                    value.class = Class::Zombie;
                }
            }
            self.after.get_mut(&identity.pid).unwrap().class = Class::Zombie;
            return Err(Failure::Errno(3));
        }
        if self.token_error {
            return Err(Failure::Mach(5));
        }
        let mut value = identity;
        if let Some(version) = self.token_version {
            value.version = version;
        }
        Ok(SignalToken {
            identity: value,
            sid,
            handle: value,
        })
    }
    fn signal_exact(&mut self, token: &Identity, signal: Signal) -> Result<(), Failure> {
        self.events.push("signal");
        if self.signal_error {
            return Err(Failure::Errno(1));
        }
        self.signals.push((*token, signal));
        Ok(())
    }
    fn observe_leader(&mut self, _child: &mut usize) -> Result<Option<i32>, Failure> {
        self.events.push("leader");
        self.leader
    }
    fn reap_leader(&mut self, child: &mut usize) -> Result<i32, Failure> {
        self.events.push("reap");
        self.reaps += 1;
        *child += 1;
        self.reap
    }
}
fn owner() -> Scope<usize, Watch> {
    Scope::new(
        0,
        Some(process(10, 100, 10).identity),
        QualifiedDarwin {
            contract: "model-xnu-contract",
        },
    )
}

#[test]
fn darwin223_direct_leader_exit_cannot_complete_with_live_descendant() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(scope.retained(), (0, 1));
    assert_eq!(model.reaps, 0);
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.reaps, 0);
    model.gone.insert(11);
    model.remove(11);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(model.reaps, 1);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(model.reaps, 1);
}

#[test]
fn darwin223_quick_exit_needs_later_strong_exclusion_not_esrch() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    model.denied.insert(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(scope.retained(), (1, 0));
    assert_eq!(model.reaps, 0);
    model.remove(11);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(model.reaps, 1);
}

#[test]
fn darwin223_cookie_exhaustion_cannot_drop_new_obligation() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    let mut scope = owner();
    scope.set_cookie_for_test(u64::MAX);
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
    model.remove(11);
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
}
#[test]
fn darwin223_reserved_leader_identity_mismatch_cannot_reap() {
    let mut model = Model::new(vec![process(10, 999, 10)]);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
}

#[test]
fn darwin223_capacity_uses_both_strict_bounds_and_checked_arithmetic() {
    use super::scope::capacity_for_test;
    assert!(capacity_for_test(20, 1));
    assert!(!capacity_for_test(21, 1));
    assert!(!capacity_for_test(CAPACITY, CAPACITY));
    assert!(!capacity_for_test(1, usize::MAX));
    // Stable final classifications cannot compensate for an incomplete raw census.
    let values = (10..31).map(|pid| process(pid, pid as u64, 99)).collect();
    let mut model = Model::new(values);
    model.before = vec![process(10, 100, 10)];
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
}

#[test]
fn darwin223_malformed_raw_cannot_certify_empty_scope() {
    for bytes in [0, 1, CAPACITY * size_of::<i32>() + 4] {
        let mut model = Model::new(vec![process(10, 100, 10)]);
        model.bytes = Some(bytes);
        assert_eq!(owner().step(&mut model), Progress::Unknown);
        assert_eq!(model.reaps, 0);
    }
    for raw in [vec![10, 10], vec![10, -1]] {
        let mut model = Model::new(vec![process(10, 100, 10)]);
        model.raw = raw;
        assert_eq!(owner().step(&mut model), Progress::Unknown);
        assert_eq!(model.reaps, 0);
    }
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.raw.push(0);
    assert_eq!(owner().step(&mut model), Progress::Complete(0));
    assert!(model.signals.is_empty());
}

#[test]
fn darwin223_identity_churn_and_session_transition_invalidate_final_pass() {
    for changed in [process(11, 999, 99), process(11, 101, 99)] {
        let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
        model.after.insert(11, changed);
        assert_eq!(owner().step(&mut model), Progress::Unknown);
        assert_eq!(model.reaps, 0);
    }
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 99)]);
    model.after.remove(&11);
    assert_eq!(owner().step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
}

#[test]
fn darwin223_retains_member_despite_later_unknown_classification() {
    let mut model = Model::new(vec![
        process(10, 100, 10),
        process(11, 101, 10),
        process(12, 102, 99),
    ]);
    model.after.remove(&12);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(scope.retained(), (0, 1));
    model.remove(12);
    model.gone.insert(11);
    model.remove(11);
    model.events.clear();
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert!(
        model.events.iter().position(|e| *e == "exit").unwrap()
            < model.events.iter().position(|e| *e == "raw").unwrap()
    );
    assert!(
        model.events.iter().position(|e| *e == "baseline").unwrap()
            < model.events.iter().position(|e| *e == "raw").unwrap()
    );
}

#[test]
fn darwin223_last_fork_requires_new_watch_and_later_pass() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    model.denied.insert(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    model.remove(11);
    let child = process(12, 102, 10);
    model.before.push(child);
    model.after.insert(12, child);
    model.raw.push(12);
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(scope.retained(), (1, 1));
    assert_eq!(model.reaps, 0);
    model.gone.insert(12);
    model.remove(12);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
}

#[test]
fn darwin223_candidate_zombie_requires_same_call_double_classification() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    model.denied.insert(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    model.after.get_mut(&11).unwrap().class = Class::Zombie;
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
    model
        .before
        .iter_mut()
        .find(|p| p.identity.pid == 11)
        .unwrap()
        .class = Class::Zombie;
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
}

#[test]
fn darwin223_lost_bound_watcher_cannot_be_downgraded_to_candidate() {
    for bad_cookie in [false, true] {
        let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
        let mut scope = owner();
        assert_eq!(scope.step(&mut model), Progress::Pending);
        model.event_error = !bad_cookie;
        model.foreign_cookie = bad_cookie;
        model.gone.insert(11);
        model.remove(11);
        assert_eq!(scope.step(&mut model), Progress::Unknown);
        assert_eq!(scope.retained(), (0, 1));
        model.event_error = false;
        model.foreign_cookie = false;
        assert_eq!(scope.step(&mut model), Progress::Unknown);
        assert_eq!(model.reaps, 0);
    }
}

#[test]
fn darwin223_exec_uses_fresh_token_and_sticky_signal_stages() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    model.after.get_mut(&11).unwrap().identity.version = 2;
    model
        .before
        .iter_mut()
        .find(|p| p.identity.pid == 11)
        .unwrap()
        .identity
        .version = 2;
    model.token_version = Some(1);
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert!(model.signals.is_empty());
    model.token_version = None;
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(
        model.signals,
        vec![(
            Identity {
                pid: 11,
                unique: 101,
                version: 2
            },
            Signal::Hup
        )]
    );
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals.len(), 1);
    scope.escalate();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals.len(), 2);
    assert_eq!(model.signals[1].1, Signal::Kill);
}

#[test]
fn darwin223_reused_foreign_pid_never_receives_old_member_signal() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    model.denied.insert(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    let reused = process(11, 999, 99);
    model.before[1] = reused;
    model.after.insert(11, reused);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert!(model.signals.is_empty());
}

#[test]
fn darwin223_leader_observation_or_reap_failure_never_retries_consuming_wait() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.reap = Err(Failure::Mach(5));
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 1);
    model.reap = Ok(0);
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 1);
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.leader = Err(Failure::Leader);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    model.leader = Ok(Some(0));
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
}

#[test]
fn darwin223_live_candidate_can_bind_after_transient_registration_failure() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    model.denied.insert(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    model.denied.clear();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(scope.retained(), (0, 1));
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals.len(), 1);
    model.gone.insert(11);
    model.remove(11);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
}

#[test]
fn darwin223_non_exit_or_error_event_never_releases_watcher() {
    for bad_event in 1..=3 {
        let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
        let mut scope = owner();
        assert_eq!(scope.step(&mut model), Progress::Pending);
        model.gone.insert(11);
        model.remove(11);
        model.bad_event = bad_event;
        assert_eq!(scope.step(&mut model), Progress::Unknown);
        assert_eq!(model.reaps, 0);
    }
}
#[test]
fn darwin223_previous_baseline_cannot_certify_later_raw_call() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.leader = Ok(None);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    model.before.clear();
    model.leader = Ok(Some(0));
    model.events.clear();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
    assert_eq!(
        model
            .events
            .iter()
            .filter(|event| **event == "baseline")
            .count(),
        1
    );
}
#[test]
fn darwin223_missing_postspawn_identity_keeps_original_child_unreaped() {
    let mut scope: Scope<usize, Watch> = Scope::new(
        0,
        None,
        QualifiedDarwin {
            contract: "model-xnu-contract",
        },
    );
    let mut model = Model::new(vec![process(10, 100, 10)]);
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert!(model.events.is_empty());
    assert_eq!(model.reaps, 0);
}
#[test]
fn darwin223_returned_new_pid_forces_fresh_preclassification() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    let child = process(11, 101, 10);
    model.after.insert(11, child);
    model.raw.push(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(scope.retained(), (0, 1));
    assert_eq!(model.reaps, 0);
    model.before.push(child);
    assert_eq!(scope.step(&mut model), Progress::Pending);
    model.gone.insert(11);
    model.remove(11);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
}

#[test]
fn darwin223_live_reserved_leader_receives_exact_sticky_hup_then_kill() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.leader = Ok(None);
    let mut scope = owner();
    scope.request_stop();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(
        model.signals,
        vec![(process(10, 100, 10).identity, Signal::Hup)]
    );
    assert_eq!(model.reaps, 0);
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals.len(), 1);
    scope.escalate();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(
        model.signals[1],
        (process(10, 100, 10).identity, Signal::Kill)
    );
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals.len(), 2);
    assert_eq!(model.reaps, 0);
    model.leader = Ok(Some(0));
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(model.reaps, 1);
    assert_eq!(model.signals.len(), 2);
}

#[test]
fn darwin223_leader_token_denial_or_staleness_never_signals_or_reaps() {
    for denial in 0..3 {
        let mut model = Model::new(vec![process(10, 100, 10)]);
        model.leader = Ok(None);
        model.token_error = denial == 0;
        model.token_version = (denial == 1).then_some(99);
        model.signal_error = denial == 2;
        let mut scope = owner();
        scope.request_stop();
        assert_eq!(scope.step(&mut model), Progress::Unknown);
        assert!(model.signals.is_empty());
        assert_eq!(model.reaps, 0);
        model.token_error = false;
        model.token_version = None;
        model.signal_error = false;
        assert_eq!(scope.step(&mut model), Progress::Pending);
        assert_eq!(model.signals.len(), 1);
        assert_eq!(model.reaps, 0);
    }
}
#[test]
fn darwin223_leader_exec_refreshes_exact_token_before_each_new_stage() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.leader = Ok(None);
    model.after.get_mut(&10).unwrap().identity.version = 2;
    model.before[0].identity.version = 2;
    let mut scope = owner();
    scope.request_stop();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals[0].0.version, 2);
    model.after.get_mut(&10).unwrap().identity.version = 3;
    model.before[0].identity.version = 3;
    scope.escalate();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(model.signals[1].0.version, 3);
    assert_eq!(model.signals[1].1, Signal::Kill);
    assert_eq!(model.reaps, 0);
}
#[test]
fn darwin223_leader_identity_or_wait_custody_loss_permanently_blocks_signals() {
    for identity_loss in [true, false] {
        let mut model = Model::new(vec![process(10, 100, 10)]);
        model.leader = Ok(None);
        if identity_loss {
            model.after.get_mut(&10).unwrap().identity.unique = 999;
        } else {
            model.leader = Err(Failure::Leader);
        }
        let mut scope = owner();
        scope.request_stop();
        assert_eq!(scope.step(&mut model), Progress::Unknown);
        model.after.insert(10, process(10, 100, 10));
        model.leader = Ok(None);
        scope.escalate();
        assert_eq!(scope.step(&mut model), Progress::Unknown);
        assert!(model.signals.is_empty());
        assert_eq!(model.reaps, 0);
    }
}
#[test]
fn darwin223_leader_exit_racing_token_waits_for_next_actual_observation() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    model.leader = Ok(None);
    model.exit_on_token = true;
    let mut scope = owner();
    scope.request_stop();
    assert_eq!(scope.step(&mut model), Progress::Unknown);
    assert_eq!(model.reaps, 0);
    assert!(model.signals.is_empty());
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(model.reaps, 1);
    assert_eq!(
        model
            .events
            .iter()
            .filter(|event| **event == "token")
            .count(),
        1
    );
}

#[test]
fn darwin223_runtime_row_requires_exact_patched_build_and_native_architecture() {
    let version =
        "Darwin Kernel Version 24.6.0: date; root:xnu-11417.140.69.713.47~2/RELEASE_ARM64_VMAPPLE";
    assert!(runtime_contract("24.6.0", version, "24H232", "arm64", "aarch64").is_some());
    for (release, version, build, machine, arch) in [
        ("24.6.1", version, "24H232", "arm64", "aarch64"),
        ("24.6.0", version, "24H233", "arm64", "aarch64"),
        ("24.6.0", version, "24H232", "x86_64", "x86_64"),
        ("24.6.0", version, "24H232", "arm64", "x86_64"),
        (
            "24.6.0",
            "root:xnu-11417.140.69.713.47~20/RELEASE_ARM64_VMAPPLE",
            "24H232",
            "arm64",
            "aarch64",
        ),
        (
            "24.6.0",
            "root:xnu-11417.140.69.713.47~2/RELEASE_ARM64_VMAPPLE root:xnu-other",
            "24H232",
            "arm64",
            "aarch64",
        ),
    ] {
        assert!(runtime_contract(release, version, build, machine, arch).is_none());
    }
}

#[test]
fn darwin223_completion_exposes_same_call_capacity_evidence() {
    let mut model = Model::new(vec![process(10, 100, 10)]);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(scope.census(), Some((1, 1, 1)));
}

#[test]
fn darwin223_candidate_receipt_is_published_only_after_actual_reap() {
    let mut model = Model::new(vec![process(10, 100, 10), process(11, 101, 10)]);
    model.denied.insert(11);
    let mut scope = owner();
    assert_eq!(scope.step(&mut model), Progress::Pending);
    assert_eq!(scope.discharged_for_test(), (0, 0));
    model.remove(11);
    assert_eq!(scope.step(&mut model), Progress::Complete(0));
    assert_eq!(scope.discharged_for_test(), (1, 0));
}
