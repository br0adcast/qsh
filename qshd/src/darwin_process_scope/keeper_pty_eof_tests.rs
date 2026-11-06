// Standalone primitive controls; existing integrated actors/qualification selectors are unchanged.
mod wire {
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
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
mod native {
    mod ipc {
        use super::super::wire::{Record, BYTES};
        use std::io::{self, Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        pub fn now() -> io::Result<u64> {
            let mut t: libc::timespec = unsafe { std::mem::zeroed() };
            if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } < 0 {
                return Err(io::Error::last_os_error());
            }
            (t.tv_sec as u64)
                .checked_mul(1_000_000_000)
                .and_then(|x| x.checked_add(t.tv_nsec as u64))
                .ok_or_else(|| io::Error::other("monotonic overflow"))
        }
        pub fn wait(fd: i32, events: i16, end: u64) -> io::Result<()> {
            loop {
                let left = end.checked_sub(now()?).filter(|x| *x > 0).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "original control end")
                })?;
                let mut p = libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                };
                let millis = left.div_ceil(1_000_000).min(i32::MAX as u64) as i32;
                let n = unsafe { libc::poll(&mut p, 1, millis) };
                if n > 0 {
                    if p.revents & libc::POLLNVAL != 0 {
                        return Err(io::Error::other("invalid IPC fd"));
                    }
                    return Ok(());
                }
                if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        pub fn send(socket: &mut UnixStream, r: Record, end: u64) -> io::Result<()> {
            let b = r.encode();
            let mut pos = 0;
            while pos < BYTES {
                if now()? >= end {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "send end"));
                }
                match socket.write(&b[pos..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => pos += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        wait(socket.as_raw_fd(), libc::POLLOUT, end)?
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        pub fn receive(socket: &mut UnixStream, end: u64) -> io::Result<[u8; BYTES]> {
            let mut b = [0; BYTES];
            let mut pos = 0;
            while pos < BYTES {
                if now()? >= end {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "receive end"));
                }
                match socket.read(&mut b[pos..]) {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(n) => pos += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        wait(socket.as_raw_fd(), libc::POLLIN, end)?
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(b)
        }
        pub fn identity(fd: i32) -> io::Result<(u64, u64, u64, u32)> {
            let mut s: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut s) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((
                s.st_dev as u64,
                s.st_rdev as u64,
                s.st_ino,
                s.st_mode as u32,
            ))
        }
    }
    use super::wire::{self, Op, Receiver, Record};
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    const WORK: u64 = 60_000_000_000;
    const SETTLEMENT: u64 = 10_000_000_000;
    const PREFLIGHT: u64 = 10_000_000_000;
    const MAX_RECORDS: usize = 8192;
    const CAPTURE: usize = 3 * 1024 * 1024; // plus1MiB independently drained libtest capture: aggregate4MiB.
    const LABELS: [(u8, bool, bool); 8] = [
        (1, true, false),
        (2, true, false),
        (3, true, false),
        (4, true, false),
        (2, false, false),
        (3, false, false),
        (2, false, true),
        (3, false, true),
    ];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Outcome {
        Zero,
        WouldBlock,
        Error(Option<i32>),
    }
    impl Outcome {
        fn closed_name(self) -> &'static str {
            match self {
                Self::Zero => "zero",
                Self::WouldBlock => "would_block",
                Self::Error(Some(code)) if code == libc::EIO => "eio",
                Self::Error(None) => "error_without_code",
                Self::Error(Some(_)) => "other_error",
            }
        }
        fn terminal(self) -> bool {
            self == Self::Zero || self == Self::Error(Some(libc::EIO))
        }
    }
    #[derive(Debug)]
    struct Primary {
        before: Outcome,
        after: Option<Outcome>,
    }
    impl Primary {
        fn agrees(&self, arm: u8) -> bool {
            match arm {
                1 | 2 => self.before.terminal(),
                3 => self.before == Outcome::WouldBlock,
                4 => {
                    self.before == Outcome::WouldBlock && self.after.is_some_and(Outcome::terminal)
                }
                _ => false,
            }
        }
    }
    struct Capture {
        file: File,
        written: usize,
        records: usize,
    }
    impl Capture {
        fn line(&mut self, text: &str) -> io::Result<()> {
            let size = text
                .len()
                .checked_add(1)
                .ok_or_else(|| io::Error::other("capture overflow"))?;
            if self.written.checked_add(size).is_none_or(|n| n > CAPTURE) {
                return Err(io::Error::other("capture ceiling"));
            }
            self.file.write_all(text.as_bytes())?;
            self.file.write_all(b"\n")?;
            self.written += size;
            self.file.flush()
        }
        fn frame(&mut self, kind: &str, r: Record) -> io::Result<()> {
            if self.records == MAX_RECORDS {
                return Err(io::Error::other("global record ceiling"));
            }
            self.records += 1;
            self.line(&format!("{kind}={}", hex::encode(r.encode())))
        }
    }
    fn error(msg: &'static str) -> io::Error {
        io::Error::other(msg)
    }
    fn os_result(n: i32) -> io::Result<()> {
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn at_end(end: u64) -> io::Result<()> {
        if ipc::now()? >= end {
            Err(io::Error::new(io::ErrorKind::TimedOut, "acceptance end"))
        } else {
            Ok(())
        }
    }
    fn private_parent(path: &Path) -> io::Result<()> {
        if !path.is_absolute() {
            return Err(error("absolute owner path required"));
        }
        let parent = path.parent().ok_or_else(|| error("parent"))?;
        let m = std::fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(error("private owner directory"));
        }
        Ok(())
    }
    fn stamp(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    struct Image {
        path: PathBuf,
        _file: File,
        stamp: (u64, u64, u64, i64, i64, i64, i64),
    }
    impl Image {
        fn recheck(&self) -> io::Result<()> {
            private_parent(&self.path)?;
            let m = std::fs::symlink_metadata(&self.path)?;
            if !m.is_file() || stamp(&m) != self.stamp {
                return Err(error("helper image path drift"));
            }
            Ok(())
        }
    }
    fn preflight() -> io::Result<(Image, Capture)> {
        let end = ipc::now()?
            .checked_add(PREFLIGHT)
            .ok_or_else(|| error("preflight end"))?;
        let path = PathBuf::from(
            std::env::var_os("QSH_PTY_EOF_HELPER")
                .ok_or_else(|| error("fixed helper path required"))?,
        );
        let digest = std::env::var("QSH_PTY_EOF_HELPER_SHA256")
            .map_err(|_| error("fixed helper digest required"))?;
        let capture = PathBuf::from(
            std::env::var_os("QSH_PTY_EOF_CAPTURE")
                .ok_or_else(|| error("fixed private capture required"))?,
        );
        private_parent(&path)?;
        private_parent(&capture)?;
        at_end(end)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != unsafe { libc::geteuid() }
            || before.mode() & 0o022 != 0
            || before.nlink() != 1
            || before.len() > 16 * 1024 * 1024
        {
            return Err(error("helper image authority"));
        }
        let mut hash = Sha256::new();
        let mut total = 0;
        let mut buf = [0; 65536];
        loop {
            at_end(end)?;
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n;
            if total > 16 * 1024 * 1024 {
                return Err(error("helper byte ceiling"));
            }
            hash.update(&buf[..n]);
        }
        let after = file.metadata()?;
        if stamp(&before) != stamp(&after) || hex::encode(hash.finalize()) != digest {
            return Err(error("helper image changed/digest"));
        }
        let image = Image {
            path,
            _file: file,
            stamp: stamp(&after),
        };
        image.recheck()?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(capture)?;
        let m = output.metadata()?;
        if !m.is_file() || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } {
            return Err(error("capture identity"));
        }
        at_end(end)?;
        Ok((
            image,
            Capture {
                file: output,
                written: 0,
                records: 0,
            },
        ))
    }
    fn pair(direct: bool) -> io::Result<(File, File)> {
        if !direct {
            let p = nix::pty::openpty(
                Some(&nix::pty::Winsize {
                    ws_row: 24,
                    ws_col: 80,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                }),
                None,
            )
            .map_err(io::Error::from)?;
            return Ok((File::from(p.master), File::from(p.slave)));
        }
        let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = unsafe { libc::open(c"/dev/ptmx".as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let master = unsafe { File::from_raw_fd(fd) };
        os_result(unsafe { libc::ioctl(fd, libc::TIOCPTYGRANT, 0) })?;
        os_result(unsafe { libc::ioctl(fd, libc::TIOCPTYUNLK, 0) })?;
        let mut name = [0u8; 128];
        os_result(unsafe { libc::ioctl(fd, libc::TIOCPTYGNAME, name.as_mut_ptr()) })?;
        let end = name
            .iter()
            .position(|x| *x == 0)
            .filter(|x| *x > 5)
            .ok_or_else(|| error("slave name length"))?;
        if !name[..end].starts_with(b"/dev/") {
            return Err(error("returned slave origin"));
        }
        let slave = unsafe { libc::open(name.as_ptr().cast(), flags) };
        if slave < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((master, unsafe { File::from_raw_fd(slave) }))
    }
    fn classify(reader: &mut dyn Read, end: u64) -> io::Result<Outcome> {
        let mut total = 0;
        let mut b = [0; 512];
        loop {
            at_end(end)?;
            match reader.read(&mut b) {
                Ok(0) => return Ok(Outcome::Zero),
                Ok(n) => {
                    total += n;
                    if total > 4096 {
                        return Err(error("PTY drain ceiling"));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Outcome::WouldBlock),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Ok(Outcome::Error(e.raw_os_error())),
            }
        }
    }
    struct Arm {
        child: Child,
        socket: Option<UnixStream>,
        spare_socket: Option<UnixStream>,
        slave: Option<File>,
        reader: Option<Box<dyn Read + Send>>,
        writer: Option<Box<dyn Write + Send>>,
        resize: Option<Box<dyn transport::shell_server::ResizeHandle>>,
        rx: Receiver,
        evidence: wire::Evidence,
        nonce: [u8; 16],
        label: (u8, bool, bool),
        sequence: u32,
        slave_fd: i32,
        master_identity: (u64, u64, u64, u32),
        slave_identity: (u64, u64, u64, u32),
        status: Option<ExitStatus>,
        release_ack: bool,
        qualification_failed: bool,
    }
    impl Arm {
        fn socket(&mut self) -> io::Result<&mut UnixStream> {
            self.socket
                .as_mut()
                .ok_or_else(|| error("missing owned IPC"))
        }
        fn send(
            &mut self,
            op: Op,
            end: u64,
            capture: &mut Capture,
            semantic: bool,
        ) -> io::Result<()> {
            let mut r = Record::new(self.nonce, self.label.0, self.sequence, op);
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| error("command sequence"))?;
            r.pid = unsafe { libc::getpid() };
            r.sid = unsafe { libc::getsid(0) };
            r.group = unsafe { libc::getpgrp() };
            capture.frame("command_attempt", r)?;
            ipc::send(self.socket()?, r, end)?;
            if semantic {
                self.evidence.command(op).map_err(io::Error::other)?;
            }
            Ok(())
        }
        fn receipt(
            &mut self,
            end: u64,
            capture: &mut Capture,
            semantic: bool,
        ) -> io::Result<Record> {
            let b = ipc::receive(self.socket()?, end)?;
            let r = self.rx.accept(&b).map_err(io::Error::other)?;
            if r.pid != self.child.id() as i32 {
                return Err(error("helper process identity"));
            }
            if semantic {
                self.evidence
                    .record_then_admit(r, |x| capture.frame("helper_receipt", x))?;
            } else {
                capture.frame("helper_receipt", r)?;
            }
            Ok(r)
        }
        fn until(&mut self, op: Op, end: u64, capture: &mut Capture) -> io::Result<Record> {
            loop {
                let r = self.receipt(end, capture, true)?;
                if r.op == op {
                    return Ok(r);
                }
            }
        }
        fn primary(&mut self, end: u64, capture: &mut Capture) -> io::Result<Primary> {
            // All fields remain inside this arm, which the campaign owns outside catch_unwind.
            drop(self.spare_socket.take());
            let ready = self.until(Op::Ready, end, capture)?;
            if (ready.dev, ready.rdev, ready.ino, ready.mode) != self.slave_identity {
                return Err(error("Ready differs from parent-created slave identity"));
            }
            drop(self.slave.take());
            capture.line("parent_slave_drop_returned syscall_close_result=not_exposed")?;
            self.send(Op::CloseSlave, end, capture, true)?;
            self.until(Op::InventoryEnd, end, capture)?;
            let reader = self
                .reader
                .as_deref_mut()
                .ok_or_else(|| error("owned reader missing"))?;
            let before = classify(reader, end)?;
            let after = if self.label.0 == 4 {
                self.send(Op::CloseAlias, end, capture, true)?;
                self.until(Op::InventoryEnd, end, capture)?;
                Some(classify(
                    self.reader
                        .as_deref_mut()
                        .ok_or_else(|| error("owned reader missing"))?,
                    end,
                )?)
            } else {
                None
            };
            Ok(Primary { before, after })
        }
        fn release_and_observe(&mut self, end: u64, capture: &mut Capture) -> io::Result<bool> {
            if self.status.is_none() {
                if let Some(s) = self.child.try_wait()? {
                    self.status = Some(s);
                }
            }
            let semantic = !self.qualification_failed;
            if let Err(e) = self.send(Op::Release, end, capture, semantic) {
                self.qualification_failed = true;
                let _ = capture.line(&format!("release_error={e:?}"));
                return Ok(self.status.is_some());
            }
            loop {
                if self.status.is_none() {
                    if let Some(s) = self.child.try_wait()? {
                        self.status = Some(s);
                    }
                }
                if ipc::now()? >= end {
                    return Ok(self.status.is_some());
                }
                match self.receipt(end, capture, semantic) {
                    Ok(r) if r.op == Op::Released => {
                        self.release_ack = true;
                        return Ok(self.status.is_some());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        self.qualification_failed = true;
                        let _ = capture.line(&format!("settlement_receipt_error={e:?}"));
                        return Ok(self.status.is_some());
                    }
                }
            }
        }
        fn close_resources(&mut self) {
            drop(self.slave.take());
            drop(self.spare_socket.take());
            drop(self.reader.take());
            drop(self.writer.take());
            drop(self.resize.take());
            drop(self.socket.take());
        }
    }
    fn create_arm(image: &Image, label: (u8, bool, bool), end: u64) -> io::Result<Arm> {
        at_end(end)?;
        image.recheck()?;
        let (master, slave) = pair(label.1)?;
        let mid = ipc::identity(master.as_raw_fd())?;
        let sid = ipc::identity(slave.as_raw_fd())?;
        if mid.3 & libc::S_IFMT as u32 != libc::S_IFCHR as u32
            || sid.3 & libc::S_IFMT as u32 != libc::S_IFCHR as u32
            || mid.1 == sid.1
        {
            return Err(error("PTY character identity"));
        }
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            let f = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            os_result(f)?;
            os_result(unsafe { libc::fcntl(fd, libc::F_SETFD, f | libc::FD_CLOEXEC) })?;
        }
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        os_result(flags)?;
        os_result(unsafe {
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
        })?;
        let (reader, writer, resize) = super::super::keeper_pty::eof_control_io(master, label.2)?;
        let (socket, child_socket) = UnixStream::pair()?;
        socket.set_nonblocking(true)?;
        child_socket.set_nonblocking(true)?;
        let ctl = child_socket.as_raw_fd();
        let sfd = slave.as_raw_fd();
        if ctl < 3 || sfd < 3 || ctl == sfd {
            return Err(error("explicit inherited descriptor admission"));
        }
        let mut nonce = [0u8; 16];
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| error("nonce unavailable"))?;
        let rx = Receiver::new(nonce, label.0);
        let evidence = wire::Evidence::new(label.0, ctl, sfd);
        let mut command = Command::new(&image.path);
        command
            .args([
                ctl.to_string(),
                sfd.to_string(),
                label.0.to_string(),
                end.to_string(),
                hex::encode(nonce),
            ])
            .env_clear()
            .env("HISTFILE", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                for fd in [ctl, sfd] {
                    let f = libc::fcntl(fd, libc::F_GETFD);
                    if f < 0 || libc::fcntl(fd, libc::F_SETFD, f & !libc::FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        at_end(end)?;
        let child = command.spawn()?;
        // No fallible call, assertion, destructor, or allocation between returned Child and complete bundle.
        Ok(Arm {
            child,
            socket: Some(socket),
            spare_socket: Some(child_socket),
            slave: Some(slave),
            reader: Some(reader),
            writer: Some(writer),
            resize: Some(resize),
            rx,
            evidence,
            nonce,
            label,
            sequence: 0,
            slave_fd: sfd,
            master_identity: mid,
            slave_identity: sid,
            status: None,
            release_ack: false,
            qualification_failed: false,
        })
    }
    // The one final custodian. It borrows the full bundle retained by Campaign.current.
    fn final_custodian(arm: &mut Arm, settlement_end: u64, capture: &mut Capture) {
        while arm.status.is_none() {
            let expired = ipc::now().map_or(true, |t| t >= settlement_end);
            if expired {
                arm.qualification_failed = true;
            }
            let _ = capture.line(&wire::final_wait_entry(
                arm.child.id(),
                arm.label,
                expired,
                arm.qualification_failed,
                arm.release_ack,
            ));
            match arm.child.wait() {
                Ok(s) => arm.status = Some(s),
                Err(e) => {
                    arm.qualification_failed = true;
                    let _ = capture.line(&format!("pending_wait_error={e:?} handle_retained=true"));
                    // Error retry backoff only, never an EOF observation or renewed acceptance end.
                    std::thread::park_timeout(std::time::Duration::from_secs(1));
                }
            }
        }
    }
    struct Campaign {
        current: Option<Arm>,
        capture: Capture,
        failed: bool,
        attempted: usize,
        settled: usize,
        disagreements: usize,
    }
    impl Campaign {
        fn run(&mut self, image: &Image, end: u64, settlement_end: u64) {
            for label in LABELS {
                if at_end(end).is_err() {
                    self.failed = true;
                    let _ = self
                        .capture
                        .line("work_deadline expired=true stop_new_pairs=true");
                    break;
                }
                match create_arm(image, label, end) {
                    Ok(arm) => self.current = Some(arm),
                    Err(e) => {
                        self.failed = true;
                        let _ = self.capture.line(&format!(
                            "setup_refusal label={label:?} error={e:?} no_returned_child=true"
                        ));
                        break;
                    }
                }
                self.attempted += 1;
                let Some(arm) = self.current.as_mut() else {
                    self.failed = true;
                    break;
                };
                let binding = self.capture.line(&format!(
                    "arm_binding arm={} direct={} normalized={} pid={} nonce={} control={} slave={} dev={} rdev={} ino={} mode={}",
                    label.0, label.1, label.2, arm.child.id(), hex::encode(arm.nonce),
                    arm.spare_socket.as_ref().map_or(-1, AsRawFd::as_raw_fd), arm.slave_fd, arm.slave_identity.0,
                    arm.slave_identity.1, arm.slave_identity.2, arm.slave_identity.3
                ));
                let begin = self.capture.line(&format!(
                    "arm_begin label={label:?} pid={} nonce={} slave_fd={} master={:?} slave={:?}",
                    arm.child.id(),
                    hex::encode(arm.nonce),
                    arm.slave_fd,
                    arm.master_identity,
                    arm.slave_identity
                ));
                let primary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    binding?;
                    begin?;
                    arm.primary(end, &mut self.capture)
                }));
                let primary = match primary {
                    Ok(r) => r,
                    Err(_) => Err(error(
                        "unexpected primary panic caught; full bundle retained",
                    )),
                };
                let unsafe_setup = primary.is_err();
                if unsafe_setup {
                    arm.qualification_failed = true;
                }
                let settlement = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    arm.release_and_observe(settlement_end, &mut self.capture)
                }));
                if !matches!(&settlement, Ok(Ok(true))) {
                    if !matches!(&settlement, Ok(Ok(false))) {
                        arm.qualification_failed = true;
                    }
                    final_custodian(arm, settlement_end, &mut self.capture);
                }
                // Child consuming wait is complete before post-exit read, resource closure, result publication.
                let elapsed = ipc::now().map_or(true, |t| t >= end);
                if elapsed {
                    arm.qualification_failed = true;
                }
                let post_caught =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        match arm.reader.as_deref_mut() {
                            Some(r) => classify(r, settlement_end),
                            None => Err(error("no post-exit reader")),
                        }
                    }));
                let post = match post_caught {
                    Ok(r) => r,
                    Err(_) => Err(error("post-exit observation panic")),
                };
                let natural = arm.status.as_ref().is_some_and(ExitStatus::success)
                    && arm.release_ack
                    && arm.evidence.complete()
                    && !arm.qualification_failed;
                let agreement = primary.as_ref().is_ok_and(|p| p.agrees(label.0));
                let wait = arm.status.as_ref().map(ToString::to_string);
                let qualification_failed = arm.qualification_failed;
                arm.close_resources();
                self.settled += 1;
                // current still owns the now-reaped Child until all resources have returned from Drop.
                let publication=self.capture.line(&format!("arm_settled label={label:?} primary={primary:?} post_exit={post:?} wait={wait:?} normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement={agreement} natural={natural}"));
                let (before, after) =
                    primary
                        .as_ref()
                        .map_or(("unavailable", "unavailable"), |p| {
                            (
                                p.before.closed_name(),
                                p.after.map_or("none", Outcome::closed_name),
                            )
                        });
                let post_name = post.as_ref().map_or("unavailable", |p| p.closed_name());
                let summary = self.capture.line(&format!("contrast arm={} direct={} normalized={} before={} after={} post={} normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement={} natural={}", label.0, label.1, label.2, before, after, post_name, agreement, natural));
                self.current = None;
                if !agreement && !unsafe_setup && natural {
                    self.disagreements += 1;
                    self.failed = true;
                }
                if unsafe_setup
                    || !natural
                    || qualification_failed
                    || publication.is_err()
                    || summary.is_err()
                {
                    self.failed = true;
                    break;
                }
                // A settled prediction disagreement is latched, not a reason to skip the next fixed label.
            }
            if self.attempted != 8 || self.settled != 8 {
                self.failed = true;
            }
            let _=self.capture.line(&format!("campaign_complete attempted={} settled={} disagreements={} failed={} current_pending={}",self.attempted,self.settled,self.disagreements,self.failed,self.current.is_some()));
        }
    }
    #[test]
    #[ignore = "Dedicated native-only lease: exact ignored selector, one test, private regular capture"]
    fn standalone_pty_eof_contrasts() {
        // Preflight may fail before any helper exists; no panic/assertion is allowed to release live custody.
        let (image, capture) = match preflight() {
            Ok(x) => x,
            Err(e) => panic!("standalone preflight refusal before child: {e:?}"),
        };
        let start = ipc::now().expect("clock before child");
        let end = start.checked_add(WORK).expect("work end before child");
        let settlement_end = end
            .checked_add(SETTLEMENT)
            .expect("settlement end before child");
        let mut campaign = Campaign {
            current: None,
            capture,
            failed: false,
            attempted: 0,
            settled: 0,
            disagreements: 0,
        };
        let outer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            campaign.run(&image, end, settlement_end)
        }));
        if outer.is_err() {
            campaign.failed = true;
            while campaign.current.is_some() {
                let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if let Some(arm) = campaign.current.as_mut() {
                        arm.qualification_failed = true;
                        let _ = arm.release_and_observe(settlement_end, &mut campaign.capture);
                        final_custodian(arm, settlement_end, &mut campaign.capture);
                        arm.close_resources();
                    }
                }));
                if cleanup.is_ok() {
                    campaign.current = None;
                } else {
                    let _=campaign.capture.line("pending_cleanup_panic full_bundle_owner_retained=true runner_lease_release_forbidden=true");
                    std::thread::park_timeout(std::time::Duration::from_secs(1));
                }
            }
        }
        // Only now, with no live helper or descriptor bundle, can libtest report a failed assertion.
        assert!(
            campaign.current.is_none() && !campaign.failed,
            "standalone contrast failed; see private bounded transcript"
        );
    }
}
