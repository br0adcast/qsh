//! `kill_child_sessions`: exact (pinned descriptors only), session-wide,
//! and never waiting.

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
        let state = if self.zombies.contains(&pid) {
            'Z'
        } else {
            'S'
        };
        Ok(
            format!("{pid} (x) {state} {ppid} {sid} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9\n")
                .into_bytes(),
        )
    }
    fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        let pid = self.alive(fd)?;
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
        for pid in pids {
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
