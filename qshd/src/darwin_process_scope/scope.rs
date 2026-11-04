use super::*;

fn certified_capacity(returned: usize, persistent: usize) -> bool {
    persistent
        .checked_add(20)
        .is_some_and(|minimum| returned < CAPACITY && returned < minimum)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Progress {
    Pending,
    Unknown,
    Complete(i32),
}

pub(super) fn leader_status(
    result: Result<Option<i32>, Failure>,
) -> transport::channel_server::LeaderStatus {
    use transport::channel_server::LeaderStatus;
    match result {
        Ok(None) => LeaderStatus::Running,
        Ok(Some(code)) => LeaderStatus::Exited { code: Some(code) },
        Err(_) => LeaderStatus::Unknown("Darwin leader custody is unconfirmed".into()),
    }
}
pub(super) fn cleanup_status(progress: Progress) -> transport::channel_server::ChildStatus {
    use transport::channel_server::ChildStatus;
    match progress {
        Progress::Pending => ChildStatus::Running,
        Progress::Unknown => {
            ChildStatus::Unknown("Darwin process scope cleanup is unconfirmed".into())
        }
        Progress::Complete(code) => ChildStatus::Reaped { code: Some(code) },
    }
}

/// Constructed only from this call's capacity evidence; not a closure proof.
struct CompleteCensus {
    generation: u64,
    returned: Vec<i32>,
}
/// Includes the same call's stable pre/post classification of every positive PID.
struct FinalPass {
    census: CompleteCensus,
    classified: Vec<Classified>,
}
struct Sweep {
    #[cfg(test)]
    evidence: Option<(u64, usize, usize)>,
    discovered: Vec<Classified>,
    final_pass: Option<FinalPass>,
    error: Option<Failure>,
}

struct UnboundCandidate {
    process: Classified,
    failed_generation: u64,
    failure: Failure,
}
struct BoundMember<W> {
    identity: Identity,
    cookie: u64,
    watch: W,
    lost: bool,
    hup: bool,
    killed: bool,
}
enum Member<W> {
    Unbound(UnboundCandidate),
    Bound(BoundMember<W>),
}
impl<W> Member<W> {
    fn identity(&self) -> Identity {
        match self {
            Self::Unbound(candidate) => candidate.process.identity,
            Self::Bound(member) => member.identity,
        }
    }
}

#[must_use = "retain the original child and every unresolved member"]
pub(super) struct Scope<C, W> {
    child: C,
    leader: Option<Identity>,
    bootstrap_pid: Option<i32>,
    qualification: QualifiedDarwin,
    members: Vec<Member<W>>,
    generation: u64,
    cookie: u64,
    phase: Option<Signal>,
    leader_hup: bool,
    leader_killed: bool,
    lost_leader: bool,
    resource_lost: bool,
    completed: Option<i32>,
    last_error: Option<Failure>,
    #[cfg(test)]
    last_census: Option<(u64, usize, usize)>,
    #[cfg(test)]
    discharged: (usize, usize),
}
impl<C, W> Scope<C, W> {
    pub(super) fn new(child: C, leader: Option<Identity>, qualification: QualifiedDarwin) -> Self {
        Self {
            child,
            leader: leader.filter(|value| value.valid()),
            bootstrap_pid: None,
            qualification,
            members: Vec::new(),
            generation: 0,
            cookie: 0,
            phase: None,
            leader_hup: false,
            leader_killed: false,
            lost_leader: false,
            resource_lost: false,
            completed: None,
            last_error: None,
            #[cfg(test)]
            last_census: None,
            #[cfg(test)]
            discharged: (0, 0),
        }
    }
    /// The caller retains the original exclusive, unreaped post-setsid/exec child.
    /// This authority permits only its first identity, never replacement of a binding.
    pub(super) fn post_handshake(
        child: C,
        pid: Option<i32>,
        initial: Result<Classified, Failure>,
        qualification: QualifiedDarwin,
    ) -> Self {
        let mut scope = Self::new(child, None, qualification);
        if let Some(pid) = pid.filter(|pid| *pid > 0) {
            scope.bootstrap_pid = Some(pid);
            scope.admit_initial(initial);
        }
        scope
    }
    fn admit_initial(&mut self, result: Result<Classified, Failure>) {
        let Some(pid) = self.bootstrap_pid else {
            return;
        };
        match result {
            Ok(value)
                if value.identity.valid()
                    && value.identity.pid == pid
                    && matches!(value.class, Class::Zombie | Class::Session(_))
                    && (value.class == Class::Zombie || value.class == Class::Session(pid)) =>
            {
                self.leader = Some(value.identity);
                self.bootstrap_pid = None;
            }
            // A failed strict metadata query supplies no positive contradiction.
            // Persistent denial retains custody but never authorizes a signal/reap.
            Err(Failure::Errno(_) | Failure::Mach(_) | Failure::Invalid) => {}
            _ => {
                self.bootstrap_pid = None;
                self.lost_leader = true;
            }
        }
    }
    pub(super) fn request_stop(&mut self) {
        self.phase.get_or_insert(Signal::Hup);
    }
    pub(super) fn escalate(&mut self) {
        self.phase = Some(Signal::Kill);
    }
    #[cfg(test)]
    pub(super) fn retained(&self) -> (usize, usize) {
        self.members
            .iter()
            .fold((0, 0), |(unbound, bound), value| match value {
                Member::Unbound(_) => (unbound + 1, bound),
                Member::Bound(_) => (unbound, bound + 1),
            })
    }
    #[cfg(test)]
    pub(super) fn census(&self) -> Option<(u64, usize, usize)> {
        self.last_census
    }
    #[cfg(test)]
    pub(super) fn discharged_for_test(&self) -> (usize, usize) {
        self.discharged
    }
    #[cfg(test)]
    pub(super) fn set_cookie_for_test(&mut self, cookie: u64) {
        self.cookie = cookie;
    }
    fn remember(&mut self, failure: Failure) {
        self.last_error.get_or_insert(failure);
    }
    fn sweep<O: Ops<C, Watch = W>>(&self, ops: &mut O, generation: u64) -> Sweep {
        let mut sweep = Sweep {
            #[cfg(test)]
            evidence: None,
            discovered: Vec::new(),
            final_pass: None,
            error: None,
        };
        let baseline = match ops.baseline() {
            Ok(value) if value.len() <= CAPACITY => value,
            Ok(_) => {
                sweep.error = Some(Failure::Capacity);
                return sweep;
            }
            Err(error) => {
                sweep.error = Some(error);
                return sweep;
            }
        };
        for (index, item) in baseline.iter().enumerate() {
            if !item.identity.valid()
                || baseline[..index]
                    .iter()
                    .any(|old| old.identity.pid == item.identity.pid)
            {
                sweep.error = Some(Failure::Invalid);
                return sweep;
            }
        }
        let mut buffer = [0; CAPACITY];
        let bytes = match ops.raw_all(&mut buffer) {
            Ok(bytes)
                if bytes != 0
                    && bytes.is_multiple_of(size_of::<i32>())
                    && bytes <= size_of_val(&buffer) =>
            {
                bytes
            }
            Ok(_) => {
                sweep.error = Some(Failure::Invalid);
                return sweep;
            }
            Err(error) => {
                sweep.error = Some(error);
                return sweep;
            }
        };
        let raw = &buffer[..bytes / size_of::<i32>()];
        for (index, pid) in raw.iter().enumerate() {
            if *pid < 0 || raw[..index].contains(pid) {
                sweep.error = Some(Failure::Invalid);
                return sweep;
            }
        }
        let persistent = baseline
            .iter()
            .filter(|before| {
                ops.confirm(before.identity)
                    .is_ok_and(|after| after.valid() && before.identity.same_process(after))
            })
            .count();
        #[cfg(test)]
        {
            sweep.evidence = Some((generation, raw.len(), persistent));
        }
        let capacity = certified_capacity(raw.len(), persistent);
        if sweep.discovered.try_reserve(CAPACITY).is_err() {
            sweep.error = Some(Failure::Capacity);
            return sweep;
        }
        let mut stable = true;
        for pid in raw.iter().copied().filter(|pid| *pid != 0) {
            match ops.classify(pid) {
                Ok(after) if after.identity.valid() && after.identity.pid == pid => {
                    let before = baseline.iter().find(|before| before.identity.pid == pid);
                    if !before.is_some_and(|before| {
                        before.identity.same_process(after.identity) && before.class == after.class
                    }) {
                        stable = false;
                    }
                    sweep.discovered.push(after);
                }
                _ => {
                    stable = false;
                    sweep.error.get_or_insert(Failure::Invalid);
                }
            }
        }
        if capacity && stable && !self.qualification.contract.is_empty() {
            let mut returned = Vec::new();
            let mut classified = Vec::new();
            if returned.try_reserve(raw.len()).is_err()
                || classified.try_reserve(sweep.discovered.len()).is_err()
            {
                sweep.error = Some(Failure::Capacity);
                return sweep;
            }
            returned.extend_from_slice(raw);
            classified.extend_from_slice(&sweep.discovered);
            sweep.final_pass = Some(FinalPass {
                census: CompleteCensus {
                    generation,
                    returned,
                },
                classified,
            });
        } else {
            sweep.error.get_or_insert(Failure::Invalid);
        }
        sweep
    }
    fn acquire<O: Ops<C, Watch = W>>(
        &mut self,
        ops: &mut O,
        process: Classified,
        generation: u64,
    ) -> bool {
        let Some(next) = self.cookie.checked_add(1) else {
            self.resource_lost = true;
            self.remember(Failure::Capacity);
            return false;
        };
        self.cookie = next;
        if self.members.len() == CAPACITY || self.members.try_reserve(1).is_err() {
            self.resource_lost = true;
            self.remember(Failure::Capacity);
            return false;
        }
        let candidate = UnboundCandidate {
            process,
            failed_generation: generation,
            failure: Failure::Invalid,
        };
        self.members.push(Member::Unbound(candidate));
        let index = self.members.len() - 1;
        self.bind_candidate(ops, index, process, generation, next);
        true
    }
    fn bind_candidate<O: Ops<C, Watch = W>>(
        &mut self,
        ops: &mut O,
        index: usize,
        process: Classified,
        generation: u64,
        cookie: u64,
    ) {
        match ops.bind_exit(process, cookie) {
            Ok(registration)
                if registration.identity.same_process(process.identity)
                    && registration.cookie == cookie =>
            {
                self.members[index] = Member::Bound(BoundMember {
                    identity: registration.identity,
                    cookie,
                    watch: registration.handle,
                    lost: false,
                    hup: false,
                    killed: false,
                });
            }
            result => {
                let failure = result.err().unwrap_or(Failure::Invalid);
                if let Member::Unbound(candidate) = &mut self.members[index] {
                    candidate.failure = failure;
                    candidate.failed_generation = generation;
                }
                self.remember(failure);
            }
        }
    }
    fn signal_leader<O: Ops<C, Watch = W>>(&mut self, ops: &mut O) -> Result<(), Failure> {
        let Some(signal) = self.phase else {
            return Ok(());
        };
        let already = if signal == Signal::Kill {
            self.leader_killed
        } else {
            self.leader_hup
        };
        if already {
            return Ok(());
        }
        let leader = self.leader.ok_or(Failure::Leader)?;
        let current = ops.classify(leader.pid)?;
        if !current.identity.same_process(leader) {
            self.lost_leader = true;
            return Err(Failure::Leader);
        }
        if current.class != Class::Session(leader.pid) {
            // A zombie may race a running observation; only the next WNOWAIT
            // and complete final census can discharge direct-child custody.
            if current.class != Class::Zombie {
                self.lost_leader = true;
            }
            return Err(Failure::Invalid);
        }
        let token = ops.acquire_signal_token(current.identity, leader.pid)?;
        if token.identity != current.identity || token.sid != leader.pid {
            return Err(Failure::Invalid);
        }
        ops.signal_exact(&token.handle, signal)?;
        if signal == Signal::Kill {
            self.leader_killed = true;
        } else {
            self.leader_hup = true;
        }
        Ok(())
    }
    fn observe_members<O: Ops<C, Watch = W>>(&mut self, ops: &mut O) -> bool {
        let mut all_exited = true;
        let mut index = 0;
        while index < self.members.len() {
            let Member::Bound(member) = &mut self.members[index] else {
                index += 1;
                continue;
            };
            if member.lost {
                all_exited = false;
                index += 1;
                continue;
            }
            match ops.observe_exit(&mut member.watch) {
                Ok(Some(event))
                    if event.pid == member.identity.pid
                        && event.cookie == member.cookie
                        && event.process_filter
                        && event.note_exit
                        && !event.error =>
                {
                    self.members.remove(index); // exact exit releases this watcher, never its cookie
                    continue;
                }
                Ok(None) => {}
                _ => {
                    member.lost = true;
                    self.last_error.get_or_insert(Failure::LostBinding);
                }
            }
            all_exited = false;
            if !member.lost {
                if let Some(signal) = self.phase {
                    let already = if signal == Signal::Kill {
                        member.killed
                    } else {
                        member.hup
                    };
                    if !already {
                        let current = ops.classify(member.identity.pid);
                        if let Ok(current) = current {
                            if current.identity.same_process(member.identity)
                                && current.class == Class::Session(self.leader.unwrap().pid)
                            {
                                match ops.acquire_signal_token(
                                    current.identity,
                                    self.leader.unwrap().pid,
                                ) {
                                    Ok(token)
                                        if token.identity == current.identity
                                            && token.sid == self.leader.unwrap().pid =>
                                    {
                                        if let Err(error) = ops.signal_exact(&token.handle, signal)
                                        {
                                            self.last_error.get_or_insert(error);
                                        } else if signal == Signal::Kill {
                                            member.killed = true;
                                        } else {
                                            member.hup = true;
                                        }
                                    }
                                    _ => {
                                        self.last_error.get_or_insert(Failure::Invalid);
                                    }
                                }
                            } else {
                                self.last_error.get_or_insert(Failure::Invalid);
                            }
                        } else {
                            self.last_error.get_or_insert(Failure::Invalid);
                        }
                    }
                }
            }
            index += 1;
        }
        all_exited
    }
    pub(super) fn poll_leader<O: Ops<C, Watch = W>>(
        &mut self,
        ops: &mut O,
    ) -> Result<Option<i32>, Failure> {
        if let Some(code) = self.completed {
            return Ok(Some(code));
        }
        if self.lost_leader || (self.leader.is_none() && self.bootstrap_pid.is_none()) {
            return Err(Failure::Leader);
        }
        let observed = ops.observe_leader(&mut self.child);
        if observed.is_ok() {
            if let Some(pid) = self.bootstrap_pid {
                self.admit_initial(ops.classify(pid));
                if self.lost_leader {
                    return Err(Failure::Leader);
                }
            }
        }
        match observed {
            Ok(Some(code)) => {
                self.request_stop();
                Ok(Some(code))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                self.remember(error);
                self.lost_leader = true;
                Err(error)
            }
        }
    }
    pub(super) fn step<O: Ops<C, Watch = W>>(&mut self, ops: &mut O) -> Progress {
        if let Some(code) = self.completed {
            return Progress::Complete(code);
        }
        if self.lost_leader || (self.leader.is_none() && self.bootstrap_pid.is_none()) {
            return Progress::Unknown;
        }
        let code = match self.poll_leader(ops) {
            Ok(code) => code,
            Err(_) => return Progress::Unknown,
        };
        if self.leader.is_none() {
            // Genuine WNOWAIT status may be published, but cleanup is incomplete.
            return Progress::Pending;
        }
        let leader_signal_failed = if code.is_none() {
            match self.signal_leader(ops) {
                Ok(()) => false,
                Err(error) => {
                    self.remember(error);
                    true
                }
            }
        } else {
            false
        };
        if self.lost_leader {
            return Progress::Unknown;
        }
        let prior_exited = self.observe_members(ops);
        let Some(generation) = self.generation.checked_add(1) else {
            self.remember(Failure::Capacity);
            return Progress::Unknown;
        };
        self.generation = generation;
        let sweep = self.sweep(ops, generation);
        #[cfg(test)]
        {
            self.last_census = sweep.evidence;
        }
        if let Some(error) = sweep.error {
            if error == Failure::Capacity {
                self.resource_lost = true;
            }
            self.remember(error);
        }
        let sid = self.leader.unwrap().pid;
        let mut new_owner = false;
        for process in &sweep.discovered {
            if process.identity.pid == sid || process.class != Class::Session(sid) {
                continue;
            }
            if let Some(index) = self
                .members
                .iter()
                .position(|member| member.identity().same_process(process.identity))
            {
                // Only a fresh positive membership observation may retry an unbound candidate.
                // A lost bound watcher is never downgraded or replaced.
                if matches!(self.members[index], Member::Unbound(_)) {
                    if let Some(cookie) = self.cookie.checked_add(1) {
                        self.cookie = cookie;
                        self.bind_candidate(ops, index, *process, generation, cookie);
                        new_owner = true;
                    } else {
                        self.resource_lost = true;
                        self.remember(Failure::Capacity);
                    }
                }
                continue;
            }
            new_owner |= self.acquire(ops, *process, generation);
        }
        let Some(pass) = sweep.final_pass else {
            return Progress::Unknown;
        };
        // Retention failure cannot erase an observed obligation, even on a later pass.
        if self.resource_lost || leader_signal_failed {
            return Progress::Unknown;
        }
        let leader = self.leader.unwrap();
        if !pass
            .classified
            .iter()
            .any(|item| item.identity.same_process(leader))
        {
            self.lost_leader = true;
            self.remember(Failure::Leader);
            return Progress::Unknown;
        }
        // Independent of acquisition success: a live descendant forbids final reap.
        let live_descendant = pass
            .classified
            .iter()
            .any(|item| item.class == Class::Session(sid) && !item.identity.same_process(leader));
        if self
            .members
            .iter()
            .any(|member| matches!(member, Member::Bound(bound) if bound.lost))
        {
            return Progress::Unknown;
        }
        if !prior_exited || new_owner || live_descendant || code.is_none() {
            return Progress::Pending;
        }
        // Candidate discharge is provisional until this entire new FinalPass succeeds.
        let discharge = self.members.iter().all(|member| match member {
            Member::Bound(_) => false,
            Member::Unbound(candidate) => {
                if pass.census.generation <= candidate.failed_generation {
                    return false;
                }
                if !pass
                    .census
                    .returned
                    .contains(&candidate.process.identity.pid)
                {
                    return true;
                }
                pass.classified
                    .iter()
                    .find(|value| value.identity.pid == candidate.process.identity.pid)
                    .is_some_and(|value| {
                        !value.identity.same_process(candidate.process.identity)
                            || value.class == Class::Zombie
                    })
            }
        });
        if !discharge {
            return Progress::Unknown;
        }
        #[cfg(test)]
        let discharged = self
            .members
            .iter()
            .fold((0, 0), |(excluded, zombie), member| {
                let Member::Unbound(candidate) = member else {
                    return (excluded, zombie);
                };
                if pass.classified.iter().any(|value| {
                    value.identity.same_process(candidate.process.identity)
                        && value.class == Class::Zombie
                }) {
                    (excluded, zombie + 1)
                } else {
                    (excluded + 1, zombie)
                }
            });
        // A consuming wait invalidates the reserved SID on every failure path.
        self.lost_leader = true;
        match ops.reap_leader(&mut self.child) {
            Ok(actual) if Some(actual) == code => {
                #[cfg(test)]
                {
                    self.discharged = discharged;
                }
                self.members.clear();
                self.completed = Some(actual);
                Progress::Complete(actual)
            }
            _ => {
                self.remember(Failure::Leader);
                Progress::Unknown
            }
        }
    }
}

#[cfg(test)]
pub(super) fn capacity_for_test(n: usize, p: usize) -> bool {
    certified_capacity(n, p)
}
