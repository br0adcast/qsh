// Fixed private PTY control wire format. No serialization of native structs.
pub const BYTES: usize = 128;
pub const MAX_INVENTORY: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    Inventory = 1,
    InventoryEnd,
    Ready,
    CloseSlave,
    ClosedSlave,
    CloseAlias,
    ClosedAlias,
    Release,
    Released,
    Refused,
    CttyOpened,
    CttyClosed,
    AliasOpened,
    Session,
    Controlling,
    Foreground,
    EnumerationClosed,
}
impl Op {
    fn decode(x: u8) -> Result<Self, &'static str> {
        Ok(match x {
            1 => Self::Inventory,
            2 => Self::InventoryEnd,
            3 => Self::Ready,
            4 => Self::CloseSlave,
            5 => Self::ClosedSlave,
            6 => Self::CloseAlias,
            7 => Self::ClosedAlias,
            8 => Self::Release,
            9 => Self::Released,
            10 => Self::Refused,
            11 => Self::CttyOpened,
            12 => Self::CttyClosed,
            13 => Self::AliasOpened,
            14 => Self::Session,
            15 => Self::Controlling,
            16 => Self::Foreground,
            17 => Self::EnumerationClosed,
            _ => return Err("unknown operation"),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub nonce: [u8; 16],
    pub arm: u8,
    pub sequence: u32,
    pub op: Op,
    pub fd: i32,
    pub errno: i32,
    pub dev: u64,
    pub rdev: u64,
    pub ino: u64,
    pub mode: u32,
    pub pid: i32,
    pub sid: i32,
    pub group: i32,
}
impl Record {
    pub fn new(nonce: [u8; 16], arm: u8, sequence: u32, op: Op) -> Self {
        Self {
            nonce,
            arm,
            sequence,
            op,
            fd: -1,
            errno: 0,
            dev: 0,
            rdev: 0,
            ino: 0,
            mode: 0,
            pid: 0,
            sid: 0,
            group: 0,
        }
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut b = [0; BYTES];
        b[..4].copy_from_slice(b"PEF1");
        b[4..20].copy_from_slice(&self.nonce);
        b[20] = self.arm;
        b[21] = self.op as u8;
        b[22] = if matches!(self.op, Op::CloseSlave | Op::CloseAlias | Op::Release) {
            1
        } else {
            2
        };
        b[24..28].copy_from_slice(&self.sequence.to_le_bytes());
        for (offset, value) in [
            (28, self.fd),
            (32, self.errno),
            (64, self.pid),
            (68, self.sid),
            (72, self.group),
        ] {
            b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(36, self.dev), (44, self.rdev), (52, self.ino)] {
            b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        b[60..64].copy_from_slice(&self.mode.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() != BYTES
            || &b[..4] != b"PEF1"
            || b[23] != 0
            || b[76..].iter().any(|x| *x != 0)
        {
            return Err("length, magic, or reserved bytes");
        }
        if !(1..=4).contains(&b[20]) {
            return Err("arm");
        }
        let op = Op::decode(b[21])?;
        let role = if matches!(op, Op::CloseSlave | Op::CloseAlias | Op::Release) {
            1
        } else {
            2
        };
        if b[22] != role {
            return Err("role");
        }
        let i = |n| i32::from_le_bytes(b[n..n + 4].try_into().unwrap());
        let u = |n| u64::from_le_bytes(b[n..n + 8].try_into().unwrap());
        Ok(Self {
            nonce: b[4..20].try_into().unwrap(),
            arm: b[20],
            op,
            sequence: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            fd: i(28),
            errno: i(32),
            dev: u(36),
            rdev: u(44),
            ino: u(52),
            mode: u32::from_le_bytes(b[60..64].try_into().unwrap()),
            pid: i(64),
            sid: i(68),
            group: i(72),
        })
    }
}
pub struct Receiver {
    nonce: [u8; 16],
    arm: u8,
    next: u32,
    inventory: usize,
}
impl Receiver {
    pub fn new(nonce: [u8; 16], arm: u8) -> Self {
        Self {
            nonce,
            arm,
            next: 0,
            inventory: 0,
        }
    }
    pub fn accept(&mut self, b: &[u8]) -> Result<Record, &'static str> {
        let r = Record::decode(b)?;
        if r.nonce != self.nonce || r.arm != self.arm || r.sequence != self.next {
            return Err("binding/order");
        }
        let next = self.next.checked_add(1).ok_or("sequence overflow")?;
        if r.op == Op::Inventory {
            if self.inventory == MAX_INVENTORY {
                return Err("inventory overflow");
            }
            self.inventory += 1;
        }
        self.next = next;
        Ok(r)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_codec_roundtrip_and_refusal_preserves_errno() {
        let mut r = Record::new([7; 16], 3, 0, Op::Refused);
        r.errno = 9;
        r.fd = 42;
        r.dev = 5;
        r.rdev = 6;
        assert_eq!(Record::decode(&r.encode()).unwrap(), r);
    }
    #[test]
    fn bindings_replay_and_corrupt_receipts_are_rejected() {
        let r = Record::new([7; 16], 2, 0, Op::Ready);
        let mut rx = Receiver::new([7; 16], 2);
        let mut bad = r;
        bad.arm = 3;
        assert!(rx.accept(&bad.encode()).is_err());
        bad = r;
        bad.nonce = [8; 16];
        assert!(rx.accept(&bad.encode()).is_err());
        assert_eq!(rx.accept(&r.encode()).unwrap(), r);
        assert!(rx.accept(&r.encode()).is_err());
        let mut b = r.encode();
        b[127] = 1;
        assert!(Record::decode(&b).is_err());
        assert!(Record::decode(&b[..127]).is_err());
        b[127] = 0;
        b[21] = 255;
        assert!(Record::decode(&b).is_err());
    }
    #[test]
    fn finite_inventory_overflow_is_a_real_receiver_refusal() {
        let mut rx = Receiver::new([1; 16], 1);
        for n in 0..MAX_INVENTORY {
            rx.accept(&Record::new([1; 16], 1, n as u32, Op::Inventory).encode())
                .unwrap();
        }
        assert!(rx
            .accept(&Record::new([1; 16], 1, MAX_INVENTORY as u32, Op::Inventory).encode())
            .is_err());
    }
}
// Full finite helper transcript admission, separate from frame/sequence admission.
type Identity = (u64, u64, u64, u32);
fn identity(r: Record) -> Identity {
    (r.dev, r.rdev, r.ino, r.mode)
}
pub struct Evidence {
    arm: u8,
    control: i32,
    slave: i32,
    phase: u8,
    enumeration: bool,
    entries: std::collections::BTreeMap<i32, Identity>,
    base: std::collections::BTreeMap<i32, Identity>,
    session: bool,
    controlling: bool,
    foreground: bool,
    ctty: Option<(i32, Identity)>,
    ctty_closed: bool,
    alias: Option<(i32, Identity)>,
    slave_closed: bool,
    alias_closed: bool,
}
impl Evidence {
    pub fn new(arm: u8, control: i32, slave: i32) -> Self {
        Self {
            arm,
            control,
            slave,
            phase: 0,
            enumeration: false,
            entries: Default::default(),
            base: Default::default(),
            session: false,
            controlling: false,
            foreground: false,
            ctty: None,
            ctty_closed: false,
            alias: None,
            slave_closed: false,
            alias_closed: false,
        }
    }
    pub fn command(&mut self, op: Op) -> Result<(), &'static str> {
        self.phase = match (self.phase, op) {
            (2, Op::CloseSlave) => 3,
            (4, Op::CloseAlias) => 5,
            (6, Op::Release) => 7,
            _ => return Err("command transition"),
        };
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.phase == 8
    }
    pub fn record_then_admit(
        &mut self,
        r: Record,
        record: impl FnOnce(Record) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        record(r)?;
        self.observe(r).map_err(std::io::Error::other)
    }
    pub fn observe(&mut self, r: Record) -> Result<(), &'static str> {
        if r.errno != 0 || r.op == Op::Refused {
            return Err("actual syscall refusal");
        }
        let id = identity(r);
        let actual = (r.fd, id);
        if self.phase >= 2 && (r.pid <= 0 || r.sid != r.pid || r.group != r.pid) {
            return Err("session identity drift");
        }
        if matches!(self.phase, 0 | 3 | 5) {
            if self.phase == 3
                && r.op == Op::ClosedSlave
                && !self.slave_closed
                && self.base.get(&self.slave) == Some(&id)
                && r.fd == self.slave
            {
                self.slave_closed = true;
                return Ok(());
            }
            if self.phase == 5
                && r.op == Op::ClosedAlias
                && !self.alias_closed
                && self.alias == Some(actual)
            {
                self.alias_closed = true;
                return Ok(());
            }
            let scan = self.phase == 0
                || (self.phase == 3 && self.slave_closed)
                || (self.phase == 5 && self.alias_closed);
            if !scan {
                return Err("missing actual close");
            }
            if r.op == Op::EnumerationClosed
                && !self.enumeration
                && r.fd >= 0
                && r.mode & 0o170000 == 0o040000
            {
                self.enumeration = true;
                return Ok(());
            }
            if r.op == Op::Inventory
                && self.enumeration
                && r.fd >= 0
                && !self.entries.contains_key(&r.fd)
            {
                let alias = if self.phase == 3 {
                    self.alias.map(|x| x.0)
                } else {
                    None
                };
                if self.phase != 0 && r.fd != self.control && Some(r.fd) != alias {
                    return Err("unexpected post-close fd");
                }
                self.entries.insert(r.fd, id);
                return Ok(());
            }
            if r.op == Op::ClosedAlias
                && self.phase == 0
                && r.fd != self.control
                && r.fd != self.slave
                && self.entries.get(&r.fd) == Some(&id)
            {
                self.entries.remove(&r.fd);
                return Ok(());
            }
            if r.op == Op::InventoryEnd && self.enumeration {
                let mut expected = vec![self.control];
                if self.phase == 0 {
                    expected.push(self.slave);
                } else if self.phase == 3 {
                    if let Some(a) = self.alias {
                        expected.push(a.0);
                    }
                }
                expected.sort_unstable();
                if self.entries.keys().copied().collect::<Vec<_>>() != expected {
                    return Err("incomplete inventory");
                }
                if self.phase == 0 {
                    if self.entries[&self.control].3 & 0o170000 != 0o140000
                        || self.entries[&self.slave].3 & 0o170000 != 0o020000
                    {
                        return Err("handoff descriptor type");
                    }
                    self.base = self.entries.clone();
                    self.phase = 1;
                } else {
                    if self.entries.get(&self.control) != self.base.get(&self.control) {
                        return Err("IPC identity changed");
                    }
                    if self.phase == 3 {
                        if let Some(a) = self.alias {
                            if self.entries.get(&a.0) != Some(&a.1) {
                                return Err("alias identity changed");
                            }
                        }
                    }
                    self.phase = if self.phase == 3 && self.alias.is_some() {
                        4
                    } else {
                        6
                    };
                }
                self.entries.clear();
                self.enumeration = false;
                return Ok(());
            }
            return Err("inventory transition");
        }
        if self.phase == 1 {
            let slave = r.fd == self.slave && self.base.get(&self.slave) == Some(&id);
            let session = r.pid > 0 && r.sid == r.pid && r.group == r.pid;
            match r.op {
                Op::Session if !self.session && slave && session => {
                    self.session = true;
                    return Ok(());
                }
                Op::Controlling
                    if self.arm >= 2
                        && self.session
                        && !self.controlling
                        && slave
                        && session =>
                {
                    self.controlling = true;
                    return Ok(());
                }
                Op::Foreground if self.controlling && !self.foreground && slave && session => {
                    self.foreground = true;
                    return Ok(());
                }
                _ => {}
            }
            let setup =
                self.session && (self.arm == 1 || (self.controlling && self.foreground));
            match r.op {
                Op::CttyOpened
                    if self.arm == 3
                        && setup
                        && self.ctty.is_none()
                        && r.fd >= 0
                        && r.mode & 0o170000 == 0o020000
                        && session =>
                {
                    self.ctty = Some(actual);
                    Ok(())
                }
                Op::CttyClosed if self.ctty == Some(actual) && !self.ctty_closed && session => {
                    self.ctty_closed = true;
                    Ok(())
                }
                Op::AliasOpened
                    if self.arm == 4
                        && setup
                        && self.alias.is_none()
                        && r.fd >= 3
                        && r.fd != self.control
                        && r.fd != self.slave
                        && self.base.get(&self.slave) == Some(&id)
                        && session =>
                {
                    self.alias = Some(actual);
                    Ok(())
                }
                Op::Ready
                    if setup
                        && slave
                        && session
                        && (self.arm != 3 || self.ctty_closed)
                        && (self.arm != 4 || self.alias.is_some()) =>
                {
                    self.phase = 2;
                    Ok(())
                }
                _ => Err("setup transition"),
            }
        } else if self.phase == 7 && r.op == Op::Released {
            self.phase = 8;
            Ok(())
        } else {
            Err("unexpected helper receipt")
        }
    }
}
// The caller retains the complete arm and has no observed consuming status.
// This record marks entry only; subsequent actual settlement is still required.
pub fn final_wait_entry(
    pid: u32,
    label: (u8, bool, bool),
    expired: bool,
    qualification_failed: bool,
    released: bool,
) -> String {
    let (arm, direct, normalized) = label;
    if !expired && !qualification_failed && released {
        format!("consuming_wait_enter pid={pid} arm={arm} direct={direct} normalized={normalized} released=true observed_status=none acceptance_expired=false full_bundle_retained=true")
    } else {
        format!("pending_child_wait pid={pid} label={label:?} acceptance_expired={expired} fallback=false full_bundle_retained=true runner_lease_release_forbidden=true")
    }
}
#[cfg(test)]
mod evidence_tests {
    use super::*;
    fn r(op: Op, fd: i32) -> Record {
        let mut r = Record::new([1; 16], 3, 0, op);
        r.fd = fd;
        r.dev = 1;
        r.rdev = 2;
        r.ino = 3;
        r.mode = 0o020600;
        r.pid = 100;
        r.sid = 100;
        r.group = 100;
        r
    }
    fn prefix(arm: u8) -> Evidence {
        let mut e = Evidence::new(arm, 40, 41);
        for (op, fd, mode) in [
            (Op::EnumerationClosed, 50, 0o040700),
            (Op::Inventory, 40, 0o140600),
            (Op::Inventory, 41, 0o020600),
            (Op::InventoryEnd, 50, 0o040700),
            (Op::Session, 41, 0o020600),
        ] {
            let mut x = r(op, fd);
            x.arm = arm;
            x.mode = mode;
            e.observe(x).unwrap();
        }
        if arm >= 2 {
            e.observe(r(Op::Controlling, 41)).unwrap();
            e.observe(r(Op::Foreground, 41)).unwrap();
        }
        e
    }
    #[test]
    fn real_ctty_close_and_ready_gate_requires_matched_actual_open() {
        let mut e = prefix(3);
        assert!(!e.complete());
        assert!(e.observe(r(Op::Ready, 41)).is_err());
        assert!(e.observe(r(Op::CttyClosed, 0)).is_err());
        e.observe(r(Op::CttyOpened, 0)).unwrap();
        let mut bad = r(Op::CttyClosed, 0);
        bad.rdev = 99;
        assert!(e.observe(bad).is_err());
        assert!(e.observe(r(Op::CttyClosed, 9)).is_err());
        e.observe(r(Op::CttyClosed, 0)).unwrap();
        e.observe(r(Op::Ready, 41)).unwrap();
        assert!(e.observe(r(Op::Ready, 41)).is_err());
    }
    #[test]
    fn actual_refusal_and_wrong_direction_cannot_complete_setup() {
        let mut e = prefix(2);
        let mut x = r(Op::Ready, 41);
        x.errno = 9;
        assert!(e.observe(x).is_err());
        assert!(e.observe(r(Op::CloseSlave, 41)).is_err());
        assert!(e.observe(r(Op::AliasOpened, 8)).is_err());
        assert!(Evidence::new(2, 40, 41).observe(r(Op::Ready, 41)).is_err());
    }
    #[test]
    fn negative_ctty_and_alias_close_identity_are_refused() {
        assert!(prefix(3).observe(r(Op::CttyOpened, -1)).is_err());
        let mut e = prefix(4);
        e.observe(r(Op::AliasOpened, 42)).unwrap();
        e.observe(r(Op::Ready, 41)).unwrap();
        e.command(Op::CloseSlave).unwrap();
        e.observe(r(Op::ClosedSlave, 41)).unwrap();
        let mut x = r(Op::EnumerationClosed, 50);
        x.mode = 0o040700;
        e.observe(x).unwrap();
        x = r(Op::Inventory, 40);
        x.mode = 0o140600;
        e.observe(x).unwrap();
        e.observe(r(Op::Inventory, 42)).unwrap();
        e.observe(r(Op::InventoryEnd, 50)).unwrap();
        e.command(Op::CloseAlias).unwrap();
        assert!(e.observe(r(Op::ClosedAlias, 43)).is_err());
        let mut x = r(Op::ClosedAlias, 42);
        x.dev = 99;
        assert!(e.observe(x).is_err());
        e.observe(r(Op::ClosedAlias, 42)).unwrap();
    }
    #[test]
    fn typed_refusal_is_recorded_before_actual_semantic_rejection() {
        let mut e = Evidence::new(2, 40, 41);
        let mut refusal = r(Op::Refused, 0);
        refusal.errno = 9;
        let mut seen = None;
        assert!(e
            .record_then_admit(refusal, |x| {
                seen = Some(x);
                Ok(())
            })
            .is_err());
        assert_eq!(seen, Some(refusal));
        // Real formatter used after Released with the earlier wait still None.
        // These fixed IDs/labels are synthetic portable inputs, never native evidence.
        let labels = [
            (1, true, false),
            (2, true, false),
            (3, true, false),
            (4, true, false),
            (2, false, false),
            (3, false, false),
            (2, false, true),
            (3, false, true),
        ];
        let mut entries: Vec<_> = labels
            .into_iter()
            .map(|label| final_wait_entry(100, label, false, false, true))
            .collect();
        assert_eq!(entries[1], "consuming_wait_enter pid=100 arm=2 direct=true normalized=false released=true observed_status=none acceptance_expired=false full_bundle_retained=true");
        for (expired, failed, released) in [
            (true, false, true),
            (false, true, true),
            (false, false, false),
        ] {
            let pending = final_wait_entry(100, labels[1], expired, failed, released);
            assert!(pending.starts_with("pending_child_wait "));
            entries.push(pending);
        }
        if let Some(path) = std::env::var_os("QSH_PTY_EOF_PORTABLE_WAIT_FIXTURE") {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .expect("fresh private portable formatter fixture");
            file.write_all((entries.join("\n") + "\n").as_bytes())
                .expect("finite portable formatter fixture");
        }
    }
}
