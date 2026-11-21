//! `kill_child_sessions`: exact (pinned descriptors only), session-wide,
//! and never waiting. And `census_sessions`, a host's check of a dead
//! owner's sessions over the same census: fail-closed.

use super::*;
use std::collections::HashMap;
use std::os::fd::AsRawFd;

/// A model of /proc: pids with their parent and session. A signalled
/// process stays as it was (slow to die) unless `dies_when_signalled`.
struct Model {
    procs: HashMap<u32, (u32, u32)>,
    fds: HashMap<i32, u32>,
    gone: Vec<u32>,
    /// Exited and unreaped.
    zombies: Vec<u32>,
    /// Reaped once that many censuses are done.
    reap_after_census: Option<(usize, u32)>,
    /// Forked during the census of that index, after it was listed.
    forks: Vec<(usize, (u32, u32, u32))>,
    /// A new member of this session appears during every census.
    forks_forever_in: Option<u32>,
    dies_when_signalled: bool,
    censuses: usize,
    signals: Vec<(u32, i32)>,
    /// Process groups other than the session's own (pid -> pgid).
    groups: HashMap<u32, u32>,
    /// Whether the kernel signals a whole process group through a
    /// descriptor (Linux 6.9 and later); `false` refuses it with `EINVAL`.
    group_signals: bool,
    /// Group signals asked for, by the pid whose descriptor carried them.
    group_signalled: Vec<(u32, i32)>,
    group_attempts: usize,
    /// The census of that index fails after listing that many processes.
    census_fails_at: Option<(usize, usize)>,
    /// Listed, but their status cannot be read.
    unreadable: Vec<u32>,
}
impl Model {
    fn new(procs: &[(u32, u32, u32)]) -> Model {
        Model {
            procs: procs
                .iter()
                .map(|&(pid, ppid, sid)| (pid, (ppid, sid)))
                .collect(),
            fds: HashMap::new(),
            gone: Vec::new(),
            zombies: Vec::new(),
            reap_after_census: None,
            forks: Vec::new(),
            forks_forever_in: None,
            dies_when_signalled: false,
            censuses: 0,
            signals: Vec::new(),
            groups: HashMap::new(),
            group_signals: false,
            group_signalled: Vec::new(),
            group_attempts: 0,
            census_fails_at: None,
            unreadable: Vec::new(),
        }
    }
    fn alive(&self, fd: &OwnedFd) -> Result<u32, Failure> {
        let pid = self.fds[&fd.as_raw_fd()];
        if self.gone.contains(&pid) {
            Err(Failure::Errno(libc::ESRCH))
        } else {
            Ok(pid)
        }
    }
    fn signalled(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self.signals.iter().map(|(pid, _)| *pid).collect();
        pids.sort();
        pids
    }
}
impl Operations for Model {
    fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        let pid = self.alive(fd)?;
        let (ppid, sid) = self.procs[&pid];
        let pgid = self.groups.get(&pid).copied().unwrap_or(sid);
        let state = if self.zombies.contains(&pid) {
            'Z'
        } else {
            'S'
        };
        Ok(
            format!("{pid} (x) {state} {ppid} {pgid} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9\n")
                .into_bytes(),
        )
    }
    fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        let pid = self.alive(fd)?;
        if self.unreadable.contains(&pid) {
            return Err(Failure::Errno(libc::EACCES));
        }
        Ok(format!("Name:\tx\nTgid:\t{pid}\nPid:\t{pid}\n").into_bytes())
    }
    fn signal(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
        let pid = self.alive(fd)?;
        self.signals.push((pid, signal));
        if self.dies_when_signalled && !self.zombies.contains(&pid) {
            self.zombies.push(pid);
        }
        Ok(())
    }
    fn signal_group(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
        let pid = self.alive(fd)?;
        self.group_attempts += 1;
        if !self.group_signals {
            return Err(Failure::Errno(libc::EINVAL));
        }
        self.group_signalled.push((pid, signal));
        Ok(())
    }
}
impl ProcOperations for Model {
    fn open_self(&mut self, _: &OwnedFd) -> Result<OwnedFd, Failure> {
        unreachable!()
    }
    fn self_identity(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
        unreachable!()
    }
    fn open_numeric(&mut self, _: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
        if self.gone.contains(&pid) || !self.procs.contains_key(&pid) {
            return Err(Failure::Errno(libc::ENOENT));
        }
        let fd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        self.fds.insert(fd.as_raw_fd(), pid);
        Ok(fd)
    }
}
impl scope::ScopeOperations for Model {
    fn census(
        &mut self,
        _: &OwnedFd,
        visit: &mut dyn FnMut(&mut Self, u32),
    ) -> Result<(), Failure> {
        let mut pids: Vec<u32> = self.procs.keys().copied().collect();
        pids.sort();
        // Forked once the list is taken: in no list before the next one.
        let forks: Vec<_> = self
            .forks
            .iter()
            .filter(|(census, _)| *census == self.censuses)
            .map(|(_, fork)| *fork)
            .collect();
        for (pid, ppid, sid) in forks {
            self.procs.insert(pid, (ppid, sid));
        }
        if let Some(sid) = self.forks_forever_in {
            self.procs.insert(1000 + self.censuses as u32, (sid, sid));
        }
        for (listed, pid) in pids.into_iter().enumerate() {
            if self.census_fails_at == Some((self.censuses, listed)) {
                self.censuses += 1;
                return Err(Failure::Errno(libc::EIO));
            }
            visit(self, pid);
        }
        self.censuses += 1;
        if let Some((_, pid)) = self.reap_after_census.filter(|(n, _)| *n == self.censuses) {
            self.gone.push(pid);
        }
        Ok(())
    }
}

fn view() -> QualifiedProc {
    QualifiedProc {
        root: std::fs::File::open("/dev/null").unwrap().into(),
    }
}

/// Every process of a child's session is signalled through its own pin --
/// the child, a job in another process group of the session -- and nothing
/// outside it, nor anyone else's child.
#[test]
fn every_member_of_a_childs_session_and_nothing_else_is_signalled() {
    let me = std::process::id();
    // 10: our child, leading session 10; 11, 12: its session (12 in a
    // job of its own); 20: our child leading 20; 30: someone else's child
    // leading 30; 31 in session 30.
    let mut model = Model::new(&[
        (10, me, 10),
        (11, 10, 10),
        (12, 11, 10),
        (20, me, 20),
        (30, 1, 30),
        (31, 30, 30),
    ]);
    let kill = kill_child_sessions(&view(), |pid| pid != 20, &mut model).unwrap();
    // Each once, though none of them has died by the next pass.
    assert_eq!(model.signalled(), [10, 11, 12]);
    assert!(model.signals.iter().all(|(_, s)| *s == libc::SIGKILL));
    assert_eq!(
        kill,
        SessionKill {
            killed: 3,
            settled: true
        }
    );
}

/// A child reaped (by its channel's scope) before its session is searched
/// is not signalled, and neither is anything found in "its" session: that
/// session ID could name another session by then.
#[test]
fn a_session_whose_leader_is_reaped_meanwhile_is_left_alone() {
    let me = std::process::id();
    let mut model = Model::new(&[(10, me, 10), (11, 10, 10)]);
    model.reap_after_census = Some((1, 10));
    let kill = kill_child_sessions(&view(), |_| true, &mut model).unwrap();
    assert_eq!(kill.killed, 0);
    assert!(kill.settled);
    assert!(model.signals.is_empty(), "{:?}", model.signals);

    let mut model = Model::new(&[(11, 1, 10)]);
    assert_eq!(
        kill_child_sessions(&view(), |_| true, &mut model)
            .unwrap()
            .killed,
        0
    );
    assert!(model.signals.is_empty());
}

/// A member that forks after the list passed it and before its own SIGKILL
/// leaves a child no list had: the members are listed again, and that
/// child, and one forked during the second list, are signalled too.
#[test]
fn a_member_forked_after_the_list_is_found_by_the_next_one() {
    let me = std::process::id();
    let mut model = Model::new(&[(10, me, 10), (11, 10, 10)]);
    model.dies_when_signalled = true;
    // Census 0 lists the children; 1 and 2 are the first two member lists.
    model.forks = vec![(1, (12, 11, 10)), (2, (13, 12, 10))];
    let kill = kill_child_sessions(&view(), |_| true, &mut model).unwrap();
    assert_eq!(model.signalled(), [10, 11, 12, 13]);
    assert_eq!(
        kill,
        SessionKill {
            killed: 4,
            settled: true
        }
    );
    // The children, three lists that each found someone, one that did not.
    assert_eq!(model.censuses, 5);
}

/// A session that has a new member at every list is given up on after
/// `KILL_PASSES` lists, and said not to have settled.
#[test]
fn a_session_that_never_stops_forking_is_given_up_on() {
    let me = std::process::id();
    let mut model = Model::new(&[(10, me, 10)]);
    model.forks_forever_in = Some(10);
    let kill = kill_child_sessions(&view(), |_| true, &mut model).unwrap();
    assert!(!kill.settled);
    assert_eq!(model.censuses, 1 + KILL_PASSES);
    assert_eq!(kill.killed, model.signals.len());
}

/// A member, or a child leading no session, that has exited and is not yet
/// reaped is not signalled and not counted as killed.
#[test]
fn an_exited_unreaped_process_is_not_counted() {
    let me = std::process::id();
    // 10 leads a session with the zombie 11; 20 is a zombie child in our
    // own session, 21 a live one.
    let mut model = Model::new(&[(10, me, 10), (11, 10, 10), (20, me, 5), (21, me, 5)]);
    model.zombies = vec![11, 20];
    let kill = kill_child_sessions(&view(), |_| true, &mut model).unwrap();
    assert_eq!(model.signalled(), [10, 21]);
    assert_eq!(
        kill,
        SessionKill {
            killed: 2,
            settled: true
        }
    );
}

/// Where the kernel can signal a whole process group through a descriptor
/// (Linux 6.9 and later), every member that leads its process group has
/// its group signalled through its own pin -- all at once, so no member of
/// that group can complete a fork past the kill -- and every member is
/// still signalled one by one, as before. Nothing else is: no group of a
/// process that leads none, no group outside the sessions.
#[test]
fn group_leaders_of_a_childs_session_have_their_groups_signalled_too() {
    let me = std::process::id();
    // 10 leads session and group 10; 11 leads job 11 of that session, with
    // 12 in it; 13 is in group 11 too but leads nothing; 30 is someone
    // else's, leading its own session and group.
    let mut model = Model::new(&[
        (10, me, 10),
        (11, 10, 10),
        (12, 11, 10),
        (13, 11, 10),
        (30, 1, 30),
    ]);
    model.groups = HashMap::from([(11, 11), (12, 11), (13, 11)]);
    model.group_signals = true;
    let kill = kill_child_sessions(&view(), |_| true, &mut model).unwrap();
    let mut groups: Vec<u32> = model.group_signalled.iter().map(|(pid, _)| *pid).collect();
    groups.sort();
    assert_eq!(groups, [10, 11], "each group through its leader, once");
    assert_eq!(model.group_attempts, 2);
    assert!(model
        .group_signalled
        .iter()
        .all(|(_, s)| *s == libc::SIGKILL));
    assert_eq!(model.signalled(), [10, 11, 12, 13]);
    assert_eq!(
        kill,
        SessionKill {
            killed: 4,
            settled: true
        }
    );
}

/// A kernel before 6.9 refuses the group flag (`EINVAL`): it is asked once,
/// and the kill goes on exactly as before -- each member through its own
/// pin, over repeated lists.
#[test]
fn a_kernel_without_group_signals_is_asked_once_and_the_lists_do_the_rest() {
    let me = std::process::id();
    let mut model = Model::new(&[(10, me, 10), (11, 10, 10), (20, me, 20)]);
    model.groups = HashMap::from([(11, 11)]);
    model.dies_when_signalled = true;
    model.forks = vec![(1, (12, 11, 10))];
    let kill = kill_child_sessions(&view(), |_| true, &mut model).unwrap();
    assert!(model.group_signalled.is_empty());
    assert_eq!(model.group_attempts, 1, "refused once, not asked again");
    assert_eq!(model.signalled(), [10, 11, 12, 20]);
    assert_eq!(
        kill,
        SessionKill {
            killed: 4,
            settled: true
        }
    );
}

/// Whether the running kernel's release is `major.minor` or later.
fn kernel_at_least(major: u32, minor: u32) -> bool {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut name) }, 0);
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) }.to_string_lossy();
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    found >= (major, minor)
}

/// What the native call is: a group signal through a pinned descriptor
/// (`PIDFD_SIGNAL_PROCESS_GROUP`), which a kernel before 6.9 refuses with
/// `EINVAL`, and which never reaches a process outside that group. Signal
/// 0 only checks.
#[test]
fn the_native_group_signal_is_exact_or_refused() {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id();
    let view = qualify_native_proc().unwrap();
    let pinned = pin(&view, pid, &mut Native).expect("our child, pinned");
    let result = Native.signal_group(&pinned.fd, 0);
    if kernel_at_least(6, 9) {
        assert!(matches!(result, Ok(())), "Linux 6.9 or later: {result:?}");
    } else {
        assert!(
            matches!(result, Err(Failure::Errno(libc::EINVAL))),
            "before Linux 6.9: {result:?}"
        );
    }
    let _ = child.kill();
    let _ = child.wait();
}

struct Exec {
    argv: [*const libc::c_char; 4],
    _strings: Vec<std::ffi::CString>,
}
// Only read in the forked child, before its exec.
unsafe impl Send for Exec {}
unsafe impl Sync for Exec {}

/// On real processes: a session leader child and a job of its session in a
/// process group of its own both die, and the child is left unreaped -- a
/// zombie only its own waiter (here the test) reaps: nothing waits.
#[test]
fn real_session_members_die_and_nothing_is_reaped() {
    use std::os::unix::process::CommandExt;
    let strings = vec![
        std::ffi::CString::new("/bin/sh").unwrap(),
        std::ffi::CString::new("-c").unwrap(),
        std::ffi::CString::new("exec sleep 301").unwrap(),
    ];
    let exec = Exec {
        argv: [
            strings[0].as_ptr(),
            strings[1].as_ptr(),
            strings[2].as_ptr(),
            std::ptr::null(),
        ],
        _strings: strings,
    };
    let mut command = std::process::Command::new("sleep");
    command.arg("300");
    unsafe {
        command.pre_exec(move || {
            // The whole wrapper, not its fields (closures capture fields).
            let exec = &exec;
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // A job of this session in a process group of its own.
            if libc::fork() == 0 {
                libc::setpgid(0, 0);
                libc::execv(exec.argv[0], exec.argv.as_ptr());
                libc::_exit(127);
            }
            Ok(())
        });
    }
    let mut leader = command.spawn().unwrap();
    let leader_pid = leader.id();
    let stat = |pid: u32| -> Option<(u8, u32, u32, u32)> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest: Vec<&str> = text[text.rfind(')')? + 2..].split(' ').collect();
        Some((
            rest[0].as_bytes()[0],
            rest[1].parse().ok()?,
            rest[2].parse().ok()?,
            rest[3].parse().ok()?,
        ))
    };
    // The job: the leader's child (until the leader execs, it is the fork).
    let mut job = None;
    for _ in 0..500 {
        job = std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .find(|&pid| {
                stat(pid).is_some_and(|(_, ppid, pgrp, sid)| {
                    ppid == leader_pid && sid == leader_pid && pgrp == pid
                }) && std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .is_ok_and(|c| c.contains("301"))
            });
        if job.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let job = job.expect("the job in its own process group");
    assert_ne!(stat(job).unwrap().2, leader_pid, "another process group");

    let view = qualify_native_proc().expect("qualified procfs");
    let kill = kill_child_sessions(&view, |pid| pid == leader_pid, &mut Native).expect("listed");
    assert_eq!(
        kill,
        SessionKill {
            killed: 2,
            settled: true
        }
    );
    let dead = |pid: u32| stat(pid).is_none_or(|(state, ..)| state == b'Z');
    for _ in 0..500 {
        if dead(job) && dead(leader_pid) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(dead(job), "the job died");
    assert_eq!(
        stat(leader_pid).map(|(state, ..)| state),
        Some(b'Z'),
        "the child died and was left unreaped"
    );
    let status = leader.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL)
    );
}

/// A session's processes, as /proc lists them now: (pid, state).
fn session_processes(sid: u32) -> Vec<(u32, u8)> {
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let rest: Vec<&str> = text[text.rfind(')')? + 2..].split(' ').collect();
            (rest[3].parse() == Ok(sid)).then(|| (pid, rest[0].as_bytes()[0]))
        })
        .collect()
}

/// Ends a test's session whatever the test did: the leader is this
/// process's unreaped child, so its number still names its process group,
/// which every process of this (job-control-free) shell session is in.
struct Session(std::process::Child);
impl Drop for Session {
    fn drop(&mut self) {
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

/// On real processes that keep forking: three shell loops, each starting
/// a long-lived child as fast as it can, are killed while they fork. No
/// process of the session is left alive: not the loops, not a child one of
/// them forked while the others were being listed and signalled.
#[test]
fn no_member_of_a_forking_session_survives() {
    use std::os::unix::process::CommandExt;
    // Bounded, so that a failure leaves a known number of processes for
    // the guard to end.
    let forks = "i=0; while [ $i -lt 1500 ]; do sleep 300 & i=$((i+1)); done; sleep 300";
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("({forks}) & ({forks}) & {forks}"))
        .stdin(std::process::Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let session = Session(command.spawn().unwrap());
    let leader_pid = session.0.id();
    // All three loops are forking.
    let mut before = 0;
    for _ in 0..1000 {
        before = session_processes(leader_pid).len();
        if before >= 40 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(before >= 40, "the session forks: {before} process(es)");

    let view = qualify_native_proc().expect("qualified procfs");
    let kill = kill_child_sessions(&view, |pid| pid == leader_pid, &mut Native).expect("listed");
    assert!(kill.settled, "{kill:?}");
    assert!(kill.killed >= before, "{kill:?}, {before} before");

    // Nothing waited for them: give the kernel time to end them, and init
    // to reap those it inherited. A survivor would sleep on.
    let alive = |sid| {
        session_processes(sid)
            .into_iter()
            .filter(|(_, state)| *state != b'Z')
            .count()
    };
    let mut left = usize::MAX;
    for _ in 0..500 {
        left = alive(leader_pid);
        if left == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(
        left, 0,
        "{left} process(es) of the session outlived the kill ({kill:?})"
    );
}

// ---- census_sessions ----------------------------------------------------------

/// pid 1, which every walk must see.
const INIT: (u32, u32, u32) = (1, 0, 1);

fn later() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(60)
}

/// A session with no process left is empty -- after both walks -- and one
/// with a process in it is not, naming it. The census goes by the session
/// ID alone: a process of a new session that reused the number (its
/// leader is not the one the session had) keeps it occupied too. Nothing
/// is ever signalled.
#[test]
fn census_finds_each_session_by_its_id_alone() {
    // 10: session 10's leftover, its leader gone; 20: a new session that
    // reused 20, someone else's; 31 and 30: session 30, nothing of 40.
    let mut model = Model::new(&[INIT, (11, 1, 10), (20, 1, 20), (30, 1, 30), (31, 30, 30)]);
    let census = census_sessions(&view(), &[10, 20, 40], later(), &mut model);
    assert_eq!(
        census,
        vec![
            SessionCensus::Occupied(vec![11]),
            SessionCensus::Occupied(vec![20]),
            SessionCensus::Empty,
        ]
    );
    assert_eq!(model.censuses, CENSUS_PASSES, "both walks, for session 40");
    assert!(model.signals.is_empty() && model.group_attempts == 0);
    // At most CENSUS_NAMED of a session's processes are named.
    let mut many: Vec<(u32, u32, u32)> = (0..10).map(|n| (50 + n, 1, 50)).collect();
    many.push(INIT);
    let census = census_sessions(&view(), &[50], later(), &mut Model::new(&many));
    assert_eq!(
        census,
        vec![SessionCensus::Occupied(
            (50..50 + CENSUS_NAMED as u32).collect()
        )]
    );
}

/// An exited process (a zombie, nothing of it running) does not keep its
/// session occupied, nor does one gone between being listed and read.
#[test]
fn census_counts_neither_zombies_nor_processes_gone_meanwhile() {
    let mut model = Model::new(&[INIT, (11, 1, 10), (12, 1, 10)]);
    model.zombies.push(11);
    model.gone.push(12);
    assert_eq!(
        census_sessions(&view(), &[10], later(), &mut model),
        vec![SessionCensus::Empty]
    );
}

/// One walk can miss a process forked behind it (the PIDs wrapped) by a
/// parent that exits before the walk reaches it; the second walk finds it.
#[test]
fn census_second_walk_finds_a_process_the_first_missed() {
    let mut model = Model::new(&[INIT]);
    // Forked during the first walk, after the list was taken.
    model.forks.push((0, (5, 1, 10)));
    assert_eq!(
        census_sessions(&view(), &[10], later(), &mut model),
        vec![SessionCensus::Occupied(vec![5])]
    );
    assert_eq!(model.censuses, 2);
}

/// Fail-closed: a walk that fails, a process that is listed but cannot be
/// read (its session cannot be told), or a census past its deadline
/// leaves every session not already found unknown -- never empty.
#[test]
fn census_that_fails_or_times_out_proves_nothing() {
    let unknown = |census: &[SessionCensus], why: &str| {
        assert!(
            matches!(&census[0], SessionCensus::Unknown(text) if text.contains(why)),
            "{census:?}"
        );
    };
    // The second walk fails: the first one's clean result does not count.
    let mut model = Model::new(&[INIT, (11, 1, 10), (30, 1, 30)]);
    model.gone.push(11);
    model.census_fails_at = Some((1, 1));
    let census = census_sessions(&view(), &[10, 30], later(), &mut model);
    unknown(&census, "could not be listed");
    assert_eq!(
        census[1],
        SessionCensus::Occupied(vec![30]),
        "found stays found"
    );

    let mut model = Model::new(&[INIT, (7, 1, 7)]);
    model.unreadable.push(7);
    unknown(
        &census_sessions(&view(), &[10], later(), &mut model),
        "process 7 could not be read",
    );

    let mut model = Model::new(&[INIT, (7, 1, 7)]);
    unknown(
        &census_sessions(&view(), &[10], std::time::Instant::now(), &mut model),
        "did not finish in time",
    );
}

/// On real processes: a session with a process in it is occupied, naming
/// it; once that process is gone the session is empty.
#[test]
fn census_of_a_real_session() {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("sleep");
    command.arg("300").stdin(std::process::Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let session = Session(command.spawn().unwrap());
    let sid = session.0.id();
    let view = qualify_native_proc().expect("qualified procfs");
    assert_eq!(
        census_sessions(&view, &[sid], later(), &mut Native),
        vec![SessionCensus::Occupied(vec![sid])]
    );
    drop(session);
    assert_eq!(
        census_sessions(&view, &[sid], later(), &mut Native),
        vec![SessionCensus::Empty]
    );
}

/// A `/proc` that hides processes (`hidepid=invisible`, `ptraceable`) hides
/// pid 1 from an account that is not root: a walk that does not see it
/// proves nothing, also when nothing it did see is in the session.
#[test]
fn census_without_pid_1_proves_nothing() {
    let mut model = Model::new(&[(11, 1, 11), (30, 1, 30)]);
    let census = census_sessions(&view(), &[10, 30, 40], later(), &mut model);
    assert_eq!(
        census[1],
        SessionCensus::Occupied(vec![30]),
        "found stays found"
    );
    for unseen in [&census[0], &census[2]] {
        assert!(
            matches!(unseen, SessionCensus::Unknown(why) if why.contains("hides processes")),
            "{census:?}"
        );
    }
    // Listed but gone by the time it is read: not seen either.
    let mut model = Model::new(&[INIT]);
    model.gone.push(1);
    assert!(matches!(
        &census_sessions(&view(), &[40], later(), &mut model)[0],
        SessionCensus::Unknown(_)
    ));
}

/// The mount's own options decide too: `hidepid` other than `0`/`off` on
/// the view's procfs device hides processes; any other entry, another
/// device's options, or `subset=pid` (which hides no process) do not. An
/// entry not found, or not procfs, proves nothing.
#[test]
fn mount_options_that_hide_processes_are_found() {
    let mountinfo = |options: &str| {
        format!(
            "22 1 0:21 / /sys rw,nosuid shared:7 - sysfs sysfs rw,hidepid=2\n\
             23 1 0:22 / /proc rw,nosuid,nodev,noexec shared:12 - proc proc {options}\n\
             24 23 0:23 / /proc/sys/fs/binfmt_misc rw master:3 - autofs systemd-1 rw\n"
        )
    };
    let proc_dev = (0, 22);
    for shown in [
        "rw",
        "rw,hidepid=0",
        "rw,hidepid=off",
        "rw,subset=pid",
        "rw,gid=4",
    ] {
        assert_eq!(
            mount_hides_processes(mountinfo(shown).as_bytes(), proc_dev),
            None,
            "{shown}"
        );
    }
    for hidden in [
        "rw,hidepid=1",
        "rw,hidepid=2",
        "rw,hidepid=invisible",
        "rw,hidepid=ptraceable",
        "rw,subset=pid,hidepid=noaccess",
        "rw,hidepid=something-new",
    ] {
        let why = mount_hides_processes(mountinfo(hidden).as_bytes(), proc_dev).expect(hidden);
        assert!(why.contains("hidepid="), "{why}");
    }
    assert!(
        mount_hides_processes(mountinfo("rw").as_bytes(), (0, 99)).is_some(),
        "no entry"
    );
    assert!(
        mount_hides_processes(mountinfo("rw").as_bytes(), (0, 21)).is_some(),
        "not procfs"
    );
    assert!(
        mount_hides_processes(b"23 1 0:22 / /proc rw", proc_dev).is_some(),
        "cut"
    );
    // This host's own /proc, as the census reads it.
    let view = qualify_native_proc().expect("qualified procfs");
    let hidden = proc_hides_processes(&view);
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let hides = mounts
        .lines()
        .any(|l| l.contains(" - proc ") && l.contains("hidepid=") && !l.contains("hidepid=0"));
    assert_eq!(hidden.is_some(), hides, "{hidden:?}");
}

/// mountinfo is bytes: a mount point that is not UTF-8 (a user's FUSE
/// mount) on another line changes nothing, while the procfs line itself must
/// be UTF-8 and parse whole -- a byte that does not decode there proves
/// nothing, even where it would decode to an accepted option.
#[test]
fn mount_options_are_read_as_bytes() {
    let mut mountinfo =
        b"40 1 0:50 / /home/u/caf\xe9 rw shared:20 - fuse.sshfs host:/ rw\n".to_vec();
    mountinfo.extend_from_slice(b"23 1 0:22 / /proc rw,nosuid shared:12 - proc proc rw\n");
    assert_eq!(mount_hides_processes(&mountinfo, (0, 22)), None);

    mountinfo.extend_from_slice(b"41 1 0:51 / /mnt/\xff\xfe rw - fuse fuse rw,hidepid=2\n");
    assert_eq!(
        mount_hides_processes(&mountinfo, (0, 22)),
        None,
        "another device"
    );

    let procfs = |options: &[u8]| {
        let mut line = b"23 1 0:22 / /proc rw shared:12 - proc proc ".to_vec();
        line.extend_from_slice(options);
        line.push(b'\n');
        line
    };
    for broken in [&b"rw,hidepid=\xff"[..], b"rw,\xe9", b"rw,hidepid=0\xc3"] {
        let why = mount_hides_processes(&procfs(broken), (0, 22)).expect("proves nothing");
        assert!(why.contains("cannot be parsed"), "{why}");
    }
}
