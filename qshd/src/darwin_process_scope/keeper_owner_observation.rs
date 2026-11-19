//! Finite, non-atomic fixture-only observations of already owned processes.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Owner {
    pub identity: [u64; 3],
    pub sid: i32,
    pub group: i32,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OwnerSet {
    pub instance: u64,
    pub roles: [Option<Owner>; 12],
    pub present: [bool; 12],
    pub disposition: Vec<u64>,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Row {
    pub fd: i32,
    pub kind: u32,
    pub dev: u64,
    pub rdev: u64,
    pub ino: u64,
    pub mode: u32,
    pub reserved: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    Binding,
    Query,
    Metadata,
    Drift,
    Deadline,
    Capacity,
    ListingLimit,
    Encoding,
}
pub(super) trait OwnerOps {
    fn now(&mut self) -> u128;
    fn snapshot(&mut self) -> Result<OwnerSet, Reason>;
    fn owner(&mut self, expected: Owner) -> Result<Owner, Reason>;
    fn list(&mut self, owner: Owner) -> Result<Vec<Row>, Reason>;
    fn vnode(&mut self, owner: Owner, row: Row) -> Result<Row, Reason>;
}
#[derive(Serialize)]
pub(super) struct RoleProjection {
    pub state: &'static str,
    pub reason: Option<Reason>,
    pub count: usize,
    pub same_slave: usize,
    pub other_character: usize,
    pub non_vnode: usize,
    pub identity_match: Option<bool>,
    pub sid_match: Option<bool>,
    pub group_match: Option<bool>,
}
#[derive(Serialize)]
pub(super) struct Projection {
    pub schema: u8,
    pub coherent: bool,
    pub complete: bool,
    pub roles: Vec<RoleProjection>,
}
const RAW_CAP: usize = 256;
const PRIVATE_CAP: usize = 65536;
const PUBLIC_CAP: usize = 8192;
const ROLE_NAMES: [&str; 12] = [
    "controller",
    "session",
    "broker",
    "actor",
    "reservation0",
    "reservation1",
    "reservation2",
    "reservation3",
    "reservation4",
    "reservation5",
    "reservation6",
    "reservation7",
];
const _: () = {
    assert!(std::mem::size_of::<Row>() == 40);
    assert!(std::mem::align_of::<Row>() == 8);
    assert!(std::mem::offset_of!(Row, fd) == 0);
    assert!(std::mem::offset_of!(Row, kind) == 4);
    assert!(std::mem::offset_of!(Row, dev) == 8);
    assert!(std::mem::offset_of!(Row, rdev) == 16);
    assert!(std::mem::offset_of!(Row, ino) == 24);
    assert!(std::mem::offset_of!(Row, mode) == 32);
    assert!(std::mem::offset_of!(Row, reserved) == 36);
};
fn checked<O: OwnerOps, T>(
    ops: &mut O,
    end: u128,
    f: impl FnOnce(&mut O) -> Result<T, Reason>,
) -> Result<T, Reason> {
    if ops.now() >= end {
        return Err(Reason::Deadline);
    }
    let result = f(ops);
    if ops.now() >= end {
        Err(Reason::Deadline)
    } else {
        result
    }
}
fn matches_owner(actual: Owner, expected: Owner) -> bool {
    expected.identity[0] > 0
        && expected.identity[0] <= i32::MAX as u64
        && expected.identity[1] > 0
        && expected.identity[2] <= u32::MAX as u64
        && expected.sid > 0
        && actual.identity == expected.identity
        && actual.sid == expected.sid
        && actual.group > 0
        && (expected.group == 0 || expected.group == actual.group)
}
fn sample(
    ops: &mut impl OwnerOps,
    owner: Owner,
    end: u128,
    used: &mut usize,
) -> Result<Vec<Row>, Reason> {
    let mut rows = checked(ops, end, |o| o.list(owner))?;
    if rows.is_empty() {
        return Err(Reason::Query);
    }
    if rows.len() > 128 {
        return Err(Reason::ListingLimit);
    }
    if *used + rows.len() > RAW_CAP {
        return Err(Reason::Capacity);
    }
    *used += rows.len();
    rows.sort_by_key(|r| r.fd);
    let mut previous = None;
    for row in &mut rows {
        if row.fd < 0
            || previous == Some(row.fd)
            || !matches!(row.kind,0..=7|9..=11)
            || row.reserved != 0
        {
            return Err(Reason::Metadata);
        }
        previous = Some(row.fd);
        if row.kind == 1 {
            let value = checked(ops, end, |o| o.vnode(owner, *row))?;
            if value.fd != row.fd
                || value.kind != 1
                || value.reserved != 0
                || value.mode & !0xffff != 0
                || value.dev != value.dev as u32 as i32 as i64 as u64
                || value.rdev != value.rdev as u32 as i32 as i64 as u64
                || !matches!(
                    value.mode & 0o170000,
                    0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
                )
            {
                return Err(Reason::Metadata);
            }
            *row = value;
        } else if row.dev != 0 || row.rdev != 0 || row.ino != 0 || row.mode != 0 {
            return Err(Reason::Metadata);
        }
    }
    Ok(rows)
}
fn role(
    ops: &mut impl OwnerOps,
    expected: Owner,
    slave: Row,
    end: u128,
    used: &mut usize,
) -> Result<(RoleProjection, Vec<Row>), Reason> {
    let before = checked(ops, end, |o| o.owner(expected))?;
    if !matches_owner(before, expected) {
        return Err(Reason::Binding);
    }
    let first = sample(ops, before, end, used)?;
    let second = sample(ops, before, end, used)?;
    let after = checked(ops, end, |o| o.owner(expected))?;
    if !matches_owner(after, expected) || before != after || first != second {
        return Err(Reason::Drift);
    }
    let same_slave = first
        .iter()
        .filter(|r| {
            r.kind == 1
                && r.mode & 0o170000 == 0o020000
                && r.dev == slave.dev
                && r.rdev == slave.rdev
                && r.ino == slave.ino
        })
        .count();
    let characters = first
        .iter()
        .filter(|r| r.kind == 1 && r.mode & 0o170000 == 0o020000)
        .count();
    let non_vnode = first.iter().filter(|r| r.kind != 1).count();
    Ok((
        RoleProjection {
            state: "complete",
            reason: None,
            count: first.len(),
            same_slave,
            other_character: characters - same_slave,
            non_vnode,
            identity_match: Some(true),
            sid_match: Some(true),
            group_match: Some(true),
        },
        first,
    ))
}
#[derive(Serialize)]
pub(super) struct Collection {
    pub projection: Projection,
    raw: Vec<Vec<Row>>,
}
fn failed(reason: Reason) -> RoleProjection {
    RoleProjection {
        state: "refused",
        reason: Some(reason),
        count: 0,
        same_slave: 0,
        other_character: 0,
        non_vnode: 0,
        identity_match: None,
        sid_match: None,
        group_match: None,
    }
}
fn unavailable_projection(reason: Reason) -> Projection {
    let mut roles: Vec<_> = (0..12).map(|_| failed(reason)).collect();
    if matches!(reason, Reason::Deadline | Reason::Drift | Reason::Capacity) {
        for role in &mut roles {
            role.state = "unknown"
        }
    }
    Projection {
        schema: 1,
        coherent: false,
        complete: false,
        roles,
    }
}
fn construct_roles(
    mut set: OwnerSet,
    controller: Result<Owner, Reason>,
) -> Result<OwnerSet, Reason> {
    set.roles[0] = match controller {
        Ok(owner) => Some(owner),
        Err(Reason::Deadline) => return Err(Reason::Deadline),
        Err(_) => None,
    };
    set.present[0] = true;
    Ok(set)
}
fn collect(ops: &mut impl OwnerOps, expected: &OwnerSet, slave: Row, end: u128) -> Collection {
    let mut result = Collection {
        projection: Projection {
            schema: 1,
            coherent: false,
            complete: false,
            roles: vec![],
        },
        raw: vec![vec![]; 12],
    };
    let baseline = checked(ops, end, |o| o.snapshot()).is_ok_and(|s| s == *expected);
    let mut global = if baseline && expected.instance != 0 && slave.mode & 0o170000 == 0o020000 {
        None
    } else {
        Some(Reason::Binding)
    };
    let mut used = 0;
    for (i, owner) in expected.roles.iter().enumerate() {
        if let Some(reason) = global {
            let mut p = failed(reason);
            p.state = "unknown";
            result.projection.roles.push(p);
            continue;
        }
        let Some(owner) = owner else {
            result
                .projection
                .roles
                .push(if i >= 4 && !expected.present[i] {
                    RoleProjection {
                        state: "not_present",
                        reason: None,
                        count: 0,
                        same_slave: 0,
                        other_character: 0,
                        non_vnode: 0,
                        identity_match: None,
                        sid_match: None,
                        group_match: None,
                    }
                } else {
                    failed(Reason::Binding)
                });
            continue;
        };
        match role(ops, *owner, slave, end, &mut used) {
            Ok((p, rows)) => {
                result.projection.roles.push(p);
                result.raw[i] = rows
            }
            Err(reason) => {
                if matches!(reason, Reason::Deadline | Reason::Capacity) {
                    global = Some(reason)
                }
                result.projection.roles.push(failed(reason))
            }
        }
        if global.is_none() {
            match checked(ops, end, |o| o.snapshot()) {
                Ok(set) if set == *expected => {}
                Ok(_) => global = Some(Reason::Drift),
                Err(e) => global = Some(e),
            }
        }
    }
    let final_set = checked(ops, end, |o| o.snapshot());
    result.projection.coherent = global.is_none() && final_set.is_ok_and(|s| s == *expected);
    result.projection.complete = result.projection.coherent
        && result
            .projection
            .roles
            .iter()
            .all(|r| matches!(r.state, "complete" | "not_present"));
    result
}
#[derive(Serialize)]
struct Public<'a> {
    schema: u8,
    source: &'a str,
    roles: [&'static str; 12],
    observation: &'a Projection,
    persistence: &'static str,
}
fn public_bytes(
    projection: &Projection,
    source: &str,
    persistence: &'static str,
) -> Result<Vec<u8>, Reason> {
    if source.len() != 64 || !source.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Reason::Encoding);
    }
    let bytes = serde_json::to_vec(&Public {
        schema: 1,
        source,
        roles: ROLE_NAMES,
        observation: projection,
        persistence,
    })
    .map_err(|_| Reason::Encoding)?;
    if bytes.len() > PUBLIC_CAP {
        Err(Reason::Encoding)
    } else {
        Ok(bytes)
    }
}
fn bounded_private(value: &impl Serialize) -> Result<Vec<u8>, Reason> {
    let b = serde_json::to_vec(value).map_err(|_| Reason::Encoding)?;
    if b.len() > PRIVATE_CAP {
        Err(Reason::Encoding)
    } else {
        Ok(b)
    }
}
#[derive(Clone, Serialize)]
pub(super) struct FailureContext {
    pub available: bool,
    pub custody_lost: Option<bool>,
    pub consumed: Option<bool>,
    pub application: &'static str,
    pub status_known: Option<bool>,
    pub session_terminal: Option<bool>,
    pub session_wait: Option<bool>,
    pub broker_terminal: Option<bool>,
    pub drained: Option<bool>,
    pub census: Option<bool>,
    pub reservations: Option<usize>,
    pub reservation_terminal: Option<usize>,
    pub reservation_wait: Option<usize>,
}
impl FailureContext {
    pub(super) fn unavailable() -> Self {
        Self {
            available: false,
            custody_lost: None,
            consumed: None,
            application: "unknown",
            status_known: None,
            session_terminal: None,
            session_wait: None,
            broker_terminal: None,
            drained: None,
            census: None,
            reservations: None,
            reservation_terminal: None,
            reservation_wait: None,
        }
    }
}
#[derive(Serialize)]
pub(super) struct RescueProjection {
    pub before: FailureContext,
    pub after: FailureContext,
    pub rescue_returned: bool,
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
pub(super) mod real {
    use super::*;
    use crate::darwin_process_scope::{
        keeper::{AdmissionDecision, FixtureAuthority, FixtureSnapshot},
        native::NativeOps,
        Class, Identity, Ops,
    };
    #[repr(C)]
    struct Error {
        domain: i32,
        code: i32,
    }
    unsafe extern "C" {
        fn qsh_scope_fixture_fds(
            pid: i32,
            rows: *mut Row,
            capacity: u32,
            count: *mut u32,
            error: *mut Error,
        ) -> i32;
        fn qsh_scope_fixture_vnode(pid: i32, fd: i32, row: *mut Row, error: *mut Error) -> i32;
    }
    fn id(i: Identity) -> [u64; 3] {
        [i.pid as u64, i.unique, i.version as u64]
    }
    fn identity(o: Owner) -> Result<Identity, Reason> {
        if o.identity[0] == 0
            || o.identity[0] > i32::MAX as u64
            || o.identity[1] == 0
            || o.identity[2] > u32::MAX as u64
        {
            return Err(Reason::Binding);
        }
        Ok(Identity {
            pid: o.identity[0] as i32,
            unique: o.identity[1],
            version: o.identity[2] as u32,
        })
    }
    pub(super) fn now() -> u128 {
        let mut t: nix::libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut t) } != 0
            || t.tv_sec < 0
            || t.tv_nsec < 0
        {
            u128::MAX
        } else {
            t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
        }
    }
    struct Native<'a> {
        authority: &'a FixtureAuthority,
        controller: Result<Owner, Reason>,
        actor: [u64; 3],
        instance: u64,
        end: u128,
    }
    fn query<T>(end: u128, f: impl FnOnce() -> Result<T, Reason>) -> Result<T, Reason> {
        if now() >= end {
            return Err(Reason::Deadline);
        }
        let value = f();
        if now() >= end {
            Err(Reason::Deadline)
        } else {
            value
        }
    }
    impl Native<'_> {
        fn set(&self) -> Result<OwnerSet, Reason> {
            let s = self.authority.snapshot().ok_or(Reason::Drift)?;
            if s.moves.len() > 16
                || s.keepers.len() > 8
                || s.reservation_identities.len() != s.keepers.len()
                || s.app != Some(self.actor[0] as i32)
                || s.custody_lost
                || s.consumed
                || s.session_wait.is_some()
                || s.session_status.is_some()
                || s.app_status.is_some()
                || s.decision != AdmissionDecision::Admit
            {
                return Err(Reason::Drift);
            }
            let mut roles = [None; 12];
            let mut present = [false; 12];
            present[..4].fill(true);
            roles[1] = s.session.map(|i| Owner {
                identity: id(i),
                sid: s.sid,
                group: s.sid,
            });
            roles[2] = s.broker.filter(|_| !s.broker_terminal).map(|i| Owner {
                identity: id(i),
                sid: s.sid,
                group: 0,
            });
            roles[3] = Some(Owner {
                identity: self.actor,
                sid: s.sid,
                group: self.actor[0] as i32,
            });
            for (slot, (i, k)) in s.reservation_identities.iter().zip(&s.keepers).enumerate() {
                present[slot + 4] = true;
                if k.2.is_none() && k.3.is_none() {
                    roles[slot + 4] = i.map(|i| Owner {
                        identity: id(i),
                        sid: s.sid,
                        group: k.1.unwrap_or(0),
                    })
                }
            }
            // Include relevant dispositions and membership, even when an identity is unavailable.
            let mut disposition = vec![
                s.app_status.is_some() as u64,
                s.session_status.is_some() as u64,
                s.session_wait.is_some() as u64,
                s.broker_terminal as u64,
                s.drained as u64,
                s.census as u64,
                s.not_started as u64,
                s.consumed as u64,
                s.broker_parent.unwrap_or(-1) as u64,
            ];
            for k in &s.keepers {
                disposition.extend([
                    k.0 as u64,
                    k.1.unwrap_or(-1) as u64,
                    k.2.unwrap_or(-1) as u64,
                    k.3.unwrap_or(-1) as u64,
                ]);
            }
            disposition.extend(s.moves.iter().map(|v| *v as u64));
            construct_roles(
                OwnerSet {
                    instance: self.instance,
                    roles,
                    present,
                    disposition,
                },
                self.controller,
            )
        }
    }
    impl OwnerOps for Native<'_> {
        fn now(&mut self) -> u128 {
            now()
        }
        fn snapshot(&mut self) -> Result<OwnerSet, Reason> {
            self.set()
        }
        fn owner(&mut self, expected: Owner) -> Result<Owner, Reason> {
            let expected_id = identity(expected)?;
            let mut ops = NativeOps;
            let classified = query(self.end, || {
                ops.classify(expected_id.pid).map_err(|_| Reason::Query)
            })?;
            if classified.identity != expected_id
                || classified.class != Class::Session(expected.sid)
            {
                return Err(Reason::Binding);
            }
            let group = query(self.end, || {
                ops.keeper_group(expected_id, expected.sid)
                    .map_err(|_| Reason::Binding)
            })?;
            Ok(Owner {
                identity: id(classified.identity),
                sid: expected.sid,
                group,
            })
        }
        fn list(&mut self, owner: Owner) -> Result<Vec<Row>, Reason> {
            let mut rows = [Row::default(); 129];
            let mut count = 0;
            let mut error = Error { domain: 0, code: 0 };
            if unsafe {
                qsh_scope_fixture_fds(
                    identity(owner)?.pid,
                    rows.as_mut_ptr(),
                    129,
                    &mut count,
                    &mut error,
                )
            } != 0
            {
                return Err(Reason::Query);
            }
            if count == 0 || count > 128 {
                return Err(Reason::Metadata);
            }
            Ok(rows[..count as usize].to_vec())
        }
        fn vnode(&mut self, owner: Owner, row: Row) -> Result<Row, Reason> {
            let mut value = Row::default();
            let mut error = Error { domain: 0, code: 0 };
            if unsafe {
                qsh_scope_fixture_vnode(identity(owner)?.pid, row.fd, &mut value, &mut error)
            } != 0
            {
                Err(Reason::Query)
            } else {
                Ok(value)
            }
        }
    }
    fn controller(end: u128) -> Result<Owner, Reason> {
        let pid = std::process::id() as i32;
        let mut ops = NativeOps;
        let c = query(end, || ops.classify(pid).map_err(|_| Reason::Binding))?;
        let Class::Session(sid) = c.class else {
            return Err(Reason::Binding);
        };
        let group = query(end, || {
            ops.keeper_group(c.identity, sid)
                .map_err(|_| Reason::Binding)
        })?;
        Ok(Owner {
            identity: id(c.identity),
            sid,
            group,
        })
    }
    #[derive(Serialize)]
    struct Private<'a> {
        schema: u8,
        nonce: &'a str,
        instance: u64,
        source: &'a str,
        expected: &'a OwnerSet,
        collection: &'a Collection,
    }
    pub(in super::super) fn observe(
        path: &std::path::Path,
        nonce: &str,
        end: u128,
        instance: Option<u64>,
        gate: bool,
        observed: Option<&crate::darwin_process_scope::keeper_pty::FixtureObservation>,
    ) -> Vec<u8> {
        use super::super::keeper_terminal_observation as actor;
        let source = actor::source_digest();
        let limit = end.min(now().saturating_add(1_000_000_000));
        let run = || -> Result<(Collection, OwnerSet, u64), Reason> {
            let instance = instance.filter(|i| *i != 0).ok_or(Reason::Binding)?;
            let observed = observed.ok_or(Reason::Binding)?;
            let s = observed.authority.snapshot().ok_or(Reason::Binding)?;
            let pid = s.app.ok_or(Reason::Binding)?;
            let mut ops = NativeOps;
            let c = query(limit, || ops.classify(pid).map_err(|_| Reason::Binding))?;
            if c.class != Class::Session(s.sid) {
                return Err(Reason::Binding);
            }
            let binding = actor::Binding {
                schema: 1,
                nonce: nonce.to_owned(),
                end,
                actor: id(c.identity),
                source: source.clone(),
            };
            let bytes = actor::read_report(path).map_err(|_| Reason::Binding)?;
            let slave =
                actor::validated_slave_key(&bytes, &binding, Some((binding.actor, s.sid)), gate)
                    .map_err(|e| match e {
                        actor::ObserverError::Deadline => Reason::Deadline,
                        _ => Reason::Binding,
                    })?;
            let mut native = Native {
                authority: &observed.authority,
                controller: controller(limit),
                actor: binding.actor,
                instance,
                end: limit,
            };
            let expected = native.set()?;
            if now() >= limit {
                return Err(Reason::Deadline);
            }
            let collection = collect(
                &mut native,
                &expected,
                Row {
                    dev: slave.dev,
                    rdev: slave.rdev,
                    ino: slave.ino,
                    mode: slave.kind,
                    ..Row::default()
                },
                limit,
            );
            Ok((collection, expected, instance))
        };
        match run() {
            Ok((collection, expected, instance)) => {
                let raw = bounded_private(&Private {
                    schema: 1,
                    nonce,
                    instance,
                    source: &source,
                    expected: &expected,
                    collection: &collection,
                });
                let persistence = if raw
                    .ok()
                    .filter(|b| b.len() <= PRIVATE_CAP)
                    .is_some_and(|b| actor::publish_owner(path, &b).is_ok())
                {
                    "saved"
                } else {
                    "refused"
                };
                public_bytes(&collection.projection, &source, persistence).unwrap_or_default()
            }
            Err(reason) => public_bytes(&unavailable_projection(reason), &source, "not_saved")
                .unwrap_or_default(),
        }
    }
    pub(in super::super) fn context(authority: &FixtureAuthority) -> FailureContext {
        let Some(s) = authority.snapshot() else {
            return FailureContext::unavailable();
        };
        context_snapshot(&s)
    }
    fn context_snapshot(s: &FixtureSnapshot) -> FailureContext {
        if s.keepers.len() > 8 {
            return FailureContext::unavailable();
        }
        FailureContext {
            available: true,
            custody_lost: Some(s.custody_lost),
            consumed: Some(s.consumed),
            application: if s.not_started {
                "not_started"
            } else if s.app_status.is_some() {
                "status_known"
            } else if s.app.is_some() {
                "admitted"
            } else {
                "unknown"
            },
            status_known: Some(s.app_status.is_some()),
            session_terminal: Some(s.session_status.is_some()),
            session_wait: Some(s.session_wait.is_some()),
            broker_terminal: Some(s.broker_terminal),
            drained: Some(s.drained),
            census: Some(s.census),
            reservations: Some(s.keepers.len()),
            reservation_terminal: Some(s.keepers.iter().filter(|k| k.2.is_some()).count()),
            reservation_wait: Some(s.keepers.iter().filter(|k| k.3.is_some()).count()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        set: OwnerSet,
        calls: usize,
        owner_calls: usize,
        snapshots: usize,
        queries: Vec<u64>,
        rows: Vec<Row>,
        zero: Option<usize>,
        fail: Option<usize>,
        vnode_fail: bool,
        second_drift: bool,
        bad_owner: Option<Owner>,
        global_drift: bool,
        expire: bool,
        busy: bool,
    }
    fn row() -> Row {
        Row {
            fd: 8,
            kind: 1,
            dev: u64::MAX,
            rdev: 7,
            ino: 9,
            mode: 0o020600,
            ..Row::default()
        }
    }
    fn fake() -> Fake {
        let roles = std::array::from_fn(|i| {
            Some(Owner {
                identity: [10 + i as u64, 100 + i as u64, 1],
                sid: 10,
                group: 10,
            })
        });
        Fake {
            set: OwnerSet {
                instance: 7,
                roles,
                present: [true; 12],
                disposition: vec![1],
            },
            calls: 0,
            owner_calls: 0,
            snapshots: 0,
            queries: vec![],
            rows: vec![row()],
            zero: None,
            fail: None,
            vnode_fail: false,
            second_drift: false,
            bad_owner: None,
            global_drift: false,
            expire: false,
            busy: false,
        }
    }
    impl OwnerOps for Fake {
        fn now(&mut self) -> u128 {
            if self.expire && self.calls > 0 {
                100
            } else {
                0
            }
        }
        fn snapshot(&mut self) -> Result<OwnerSet, Reason> {
            if self.busy {
                return Err(Reason::Binding);
            }
            self.snapshots += 1;
            let mut s = self.set.clone();
            if self.global_drift && self.snapshots > 1 {
                s.disposition.push(2)
            }
            Ok(s)
        }
        fn owner(&mut self, o: Owner) -> Result<Owner, Reason> {
            self.owner_calls += 1;
            Ok(self.bad_owner.unwrap_or(o))
        }
        fn list(&mut self, o: Owner) -> Result<Vec<Row>, Reason> {
            self.calls += 1;
            self.queries.push(o.identity[0]);
            if self.fail == Some(self.calls) {
                return Err(Reason::Query);
            }
            if self.zero == Some(self.calls) {
                return Ok(vec![]);
            }
            let mut r = self.rows.clone();
            if self.second_drift && self.calls.is_multiple_of(2) {
                r[0].fd += 1
            }
            Ok(r)
        }
        fn vnode(&mut self, _: Owner, r: Row) -> Result<Row, Reason> {
            if self.vnode_fail {
                Err(Reason::Query)
            } else {
                Ok(r)
            }
        }
    }
    fn run(f: &mut Fake) -> Projection {
        collect(f, &f.set.clone(), row(), 100).projection
    }
    #[test]
    fn accepts_bracketed_slave_match() {
        let mut f = fake();
        let c = run(&mut f);
        assert!(c.complete);
        assert_eq!(f.calls, 24);
        assert!(c
            .roles
            .iter()
            .all(|r| r.same_slave == 1 && r.identity_match == Some(true)));
    }
    #[test]
    fn high_bit_devices_match_actor_conversion() {
        for value in [0x80000001u32, 0xffffffff, 0x7fffffff] {
            let canonical = value as i32 as i64 as u64;
            let mut f = fake();
            f.rows[0].dev = canonical;
            f.rows[0].rdev = canonical;
            let mut slave = row();
            slave.dev = canonical;
            slave.rdev = canonical;
            let c = collect(&mut f, &fake().set, slave, 100).projection;
            assert!(c.complete);
            assert_eq!(c.roles[0].same_slave, 1);
        }
    }
    #[test]
    fn master_other_character_and_non_vnodes() {
        let mut f = fake();
        f.rows[0].ino += 1;
        f.rows.push(Row {
            fd: 9,
            kind: 2,
            ..Row::default()
        });
        let c = run(&mut f);
        assert!(c.complete);
        let r = &c.roles[0];
        assert_eq!((r.same_slave, r.other_character, r.non_vnode), (0, 1, 1));
    }
    #[test]
    fn no_match_and_absent_slots() {
        let mut f = fake();
        f.rows[0].mode = 0o100600;
        for i in 4..12 {
            f.set.roles[i] = None;
            f.set.present[i] = false
        }
        let c = run(&mut f);
        assert!(c.complete);
        assert!(c.roles[4..].iter().all(|r| r.state == "not_present"));
    }
    #[test]
    fn actor_zero_continues_other_roles() {
        let mut f = fake();
        f.zero = Some(7);
        let c = run(&mut f);
        assert!(!c.complete);
        assert!(c.coherent);
        assert_eq!(c.roles[3].state, "refused");
        for i in [1, 2, 4, 11] {
            assert_eq!(c.roles[i].state, "complete");
            assert!(f.queries.contains(&(10 + i as u64)));
        }
    }
    #[test]
    fn local_query_failure_continues() {
        let mut f = fake();
        f.fail = Some(1);
        let c = run(&mut f);
        assert_eq!(c.roles[0].state, "refused");
        assert!(c.roles[1..].iter().all(|r| r.state == "complete"));
    }
    #[test]
    fn global_drift_marks_remaining_unknown() {
        let mut f = fake();
        f.global_drift = true;
        let c = run(&mut f);
        assert!(!c.coherent);
        assert_eq!(c.roles[0].state, "complete");
        assert!(c.roles[1..].iter().all(|r| r.state == "unknown"));
        assert_eq!(f.calls, 2);
    }
    #[test]
    fn budget_exhaustion_stops() {
        let mut f = fake();
        f.expire = true;
        let c = run(&mut f);
        assert!(!c.complete);
        assert!(c.roles[1..].iter().all(|r| r.state == "unknown"));
        assert_eq!(f.calls, 1);
    }
    #[test]
    fn identity_sid_version_mismatch() {
        for mutation in 0..4 {
            let mut f = fake();
            let mut o = f.set.roles[0].unwrap();
            match mutation {
                0 => o.identity[0] += 1,
                1 => o.identity[1] += 1,
                2 => o.identity[2] += 1,
                _ => o.sid += 1,
            };
            f.bad_owner = Some(o);
            let c = run(&mut f);
            assert_eq!(c.roles[0].state, "refused");
            assert_eq!(c.roles[0].identity_match, None);
        }
    }
    #[test]
    fn missing_identity_is_not_absent() {
        let mut f = fake();
        f.set.roles[4] = None;
        let c = run(&mut f);
        assert!(!c.complete);
        assert_eq!(c.roles[4].state, "refused");
        assert_eq!(c.roles[5].state, "complete");
    }
    #[test]
    fn busy_snapshot_is_unknown() {
        let mut f = fake();
        f.busy = true;
        let c = run(&mut f);
        assert!(c.roles.iter().all(|r| r.state == "unknown"));
        assert_eq!(f.calls, 0);
    }
    #[test]
    fn duplicate_negative_unknown_and_malformed() {
        for mutation in 0..4 {
            let mut f = fake();
            match mutation {
                0 => f.rows.push(row()),
                1 => f.rows[0].fd = -1,
                2 => f.rows[0].kind = 8,
                _ => f.rows[0].reserved = 1,
            };
            let c = run(&mut f);
            assert_eq!(c.roles[0].state, "refused");
            assert!(matches!(c.roles[0].reason, Some(Reason::Metadata)));
        }
    }
    #[test]
    fn vnode_failure_and_second_drift() {
        for drift in [false, true] {
            let mut f = fake();
            f.vnode_fail = !drift;
            f.second_drift = drift;
            let c = run(&mut f);
            assert_eq!(c.roles[0].state, "refused");
            assert!(!c.complete);
        }
    }
    #[test]
    fn bounds_128_129_and_total_256_257() {
        for size in [128, 129] {
            let mut f = fake();
            f.rows = (0..size)
                .map(|fd| Row {
                    fd,
                    kind: 2,
                    ..Row::default()
                })
                .collect();
            let c = run(&mut f);
            assert_eq!(
                c.roles[0].state,
                if size == 128 { "complete" } else { "refused" }
            );
            assert!(!c.complete);
            if size == 128 {
                assert!(c.roles[2..].iter().all(|r| r.state == "unknown"));
            } else {
                assert!(c.roles.iter().all(|r| r.state == "refused"));
            }
        }
        let mut used = 256;
        let mut f = fake();
        assert!(matches!(
            sample(&mut f, fake().set.roles[0].unwrap(), 100, &mut used),
            Err(Reason::Capacity)
        ));
    }
    #[test]
    fn projection_has_no_raw_identifiers() {
        let mut f = fake();
        f.set.roles[0].as_mut().unwrap().identity[1] = 987654321;
        f.rows[0].ino = 123456789;
        let c = run(&mut f);
        let bytes = public_bytes(&c, &"a".repeat(64), "not_saved").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for sentinel in [
            "987654321",
            "123456789",
            "/dev/",
            "identity\"",
            "nonce",
            "instance",
        ] {
            assert!(!text.contains(sentinel));
        }
    }
    #[test]
    fn actual_rescue_bool_and_unknown_context() {
        let before = FailureContext::unavailable();
        for rescue_returned in [true, false] {
            let mut after = before.clone();
            after.available = true;
            after.custody_lost = Some(true);
            after.consumed = Some(false);
            let p = RescueProjection {
                before: before.clone(),
                after,
                rescue_returned,
            };
            let v = serde_json::to_value(p).unwrap();
            assert_eq!(v["rescue_returned"], rescue_returned);
            assert!(v["before"]["consumed"].is_null());
            assert_eq!(v["after"]["custody_lost"], true);
        }
    }
    #[test]
    fn encoding_caps() {
        assert!(public_bytes(
            &run(&mut fake()),
            &"/PRIVATE/CANARY".repeat(1000),
            "refused"
        )
        .is_err());
        assert!(bounded_private(&vec!["x".repeat(PRIVATE_CAP)]).is_err());
        assert!(bounded_private(&vec!["x".repeat(PRIVATE_CAP - 16)]).is_ok());
    }
    #[test]
    fn wrong_instance_refuses_without_queries() {
        let mut f = fake();
        let mut set = f.set.clone();
        set.instance += 1;
        let c = collect(&mut f, &set, row(), 100);
        assert!(!c.projection.complete);
        assert_eq!(f.calls, 0);
    }
    #[test]
    fn actual_consumed_and_failed_contexts_are_distinct() {
        let mut before = FailureContext::unavailable();
        before.available = true;
        before.consumed = Some(true);
        let mut after = before.clone();
        after.custody_lost = Some(true);
        let p = RescueProjection {
            before,
            after,
            rescue_returned: true,
        };
        let v = serde_json::to_value(p).unwrap();
        assert_eq!(v["before"]["consumed"], true);
        assert_eq!(v["after"]["custody_lost"], true);
        assert!(v["before"]["custody_lost"].is_null());
    }
    #[test]
    fn observation_hooks_leave_proof_and_one_rescue_call_intact() {
        let source = include_str!("keeper_integration_tests.rs");
        let finish = source
            .split("async fn finish(mut self, body_ok: bool)")
            .nth(1)
            .unwrap()
            .split("fn monotonic()")
            .next()
            .unwrap();
        assert_eq!(
            finish
                .matches(".rescue(Instant::now() + Duration::from_secs(10))")
                .count(),
            1
        );
        assert!(finish.find("phase=before").unwrap() < finish.find("let rescue_returned").unwrap());
        assert!(
            finish.find("phase=after").unwrap()
                < finish.find("failure_final_manager_wait_entry").unwrap()
        );
        // #548: the last manager wait after rescue is bounded, never bare.
        assert!(!finish.contains("self.manager.await"));
        let bounded = finish
            .find("let result = super::wait_or_end_blocked(")
            .unwrap();
        assert!(finish.find("failure_final_manager_wait_entry").unwrap() < bounded);
        assert!(finish[bounded..].starts_with(
            "let result = super::wait_or_end_blocked(\n                        &mut self.manager,\n                        FAILURE_MANAGER_BOUND,"
        ));
        let terminal = source
            .split("pub(super) fn terminal()")
            .nth(1)
            .unwrap()
            .split("pub(super) fn cancel_setup()")
            .next()
            .unwrap();
        assert!(
            terminal.find("terminal_observation(&path").unwrap()
                < terminal.find("super::terminal_eof_until").unwrap()
        );
        assert!(terminal.contains("for kind in [ChannelKind::Shell,ChannelKind::Command]"));
    }
    #[test]
    fn malformed_device_bits_refuse_instead_of_false_no_match() {
        let mut f = fake();
        f.rows[0].dev = 0x80000001;
        let c = run(&mut f);
        assert!(matches!(c.roles[0].reason, Some(Reason::Metadata)));
        assert!(!c.complete);
    }
    #[test]
    fn public_encoding_cap_rejects_oversized_projection() {
        let mut p = run(&mut fake());
        p.roles = (0..1024).map(|_| failed(Reason::Binding)).collect();
        assert!(public_bytes(&p, &"a".repeat(64), "refused").is_err());
    }
    #[test]
    fn construction_controller_failure_preserves_other_owner_queries() {
        for failure in [Reason::Query, Reason::Binding] {
            let mut f = fake();
            let prepared = construct_roles(f.set.clone(), Err(failure)).unwrap_or_else(|_| {
                panic!("controller-local failure must remain an admitted present/refused role")
            });
            f.set = prepared.clone();
            let c = collect(&mut f, &prepared, row(), 100);
            assert_eq!(c.projection.roles[0].state, "refused");
            assert!(!c.projection.complete);
            for i in [1, 2, 3, 4, 11] {
                assert_eq!(c.projection.roles[i].state, "complete");
                assert!(f.queries.contains(&(10 + i as u64)));
            }
        }
    }

    #[test]
    fn construction_deadline_stops_unknown_without_queries() {
        let mut f = fake();
        let error = construct_roles(f.set.clone(), Err(Reason::Deadline))
            .err()
            .unwrap();
        let projection = unavailable_projection(error);
        assert!(projection.roles.iter().all(|r| r.state == "unknown"));
        assert!(!projection.complete);
        assert_eq!(f.calls, 0);
        f.global_drift = true;
        let c = run(&mut f);
        assert!(c.roles[1..].iter().all(|r| r.state == "unknown"));
    }
}
