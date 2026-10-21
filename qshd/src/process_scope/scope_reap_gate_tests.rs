#[test]
fn worker40_deferred_final_reap_requires_a_fresh_later_census() {
    let (mut scope, mut ops, events) = fixture(true, vec![Ok(vec![]), Ok(vec![])]);
    scope.request_stop();
    let held = scope.step_without_reap(&mut ops);
    let held_reaps = events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| **event == "reap")
        .count();
    let final_result = scope.step(&mut ops);
    assert_eq!(held, Progress::Pending);
    assert_eq!(held_reaps, 0);
    assert_eq!(final_result, Progress::Complete(0));
    assert_eq!(ops.calls, ["census", "census"]);
    let count = ops.calls.len();
    assert_eq!(scope.step_without_reap(&mut ops), Progress::Complete(0));
    assert_eq!(
        ops.calls.len(),
        count,
        "latched completion creates no new wait"
    );
}

#[test]
fn worker40_native_deferred_final_reap_preserves_the_real_waitable_leader() {
    use crate::process_scope::{fork_child::ForkChild, Native};
    use std::{
        io,
        num::NonZeroU32,
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    struct FixtureChild {
        child: std::process::Child,
        reaped: bool,
    }
    impl Drop for FixtureChild {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                Err(error) => panic!("owned gate fixture wait failed: {error}"),
                Ok(None) => {}
            }
            let _ = self.child.kill();
            loop {
                match self.child.wait() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => {
                        result.unwrap();
                        break;
                    }
                }
            }
        }
    }
    let view = crate::process_scope::prepare().unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "exit 7"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the fork child performs only setsid and returns through exec's
    // private error pipe; spawn success proves this controlled setup succeeded.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut fixture = FixtureChild {
        child: command.spawn().unwrap(),
        reaped: false,
    };
    let pid = NonZeroU32::new(fixture.child.id()).unwrap();
    let mut child = ForkChild::new(pid);
    let deadline = Instant::now() + Duration::from_secs(2);
    let exited = loop {
        if matches!(child.observe(), Ok(Some(7))) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let mut scope = Scope::new(child, view);
    scope.request_stop();
    let held: Vec<_> = (0..3)
        .map(|_| scope.step_without_reap(&mut Native))
        .collect();
    // This independent observation is WNOWAIT only: it never competes with the
    // retained scope's consuming wait. A latched synthetic code cannot satisfy it.
    let still_waitable = ForkChild::new(pid).observe();
    let final_result = scope.step(&mut Native);
    fixture.reaped = matches!(final_result, Progress::Complete(_));
    drop(fixture); // every failure still cleans only this exact fixture child
    assert!(exited, "deadline is failure, never exit proof");
    assert!(
        held.iter().all(|progress| *progress == Progress::Pending),
        "{held:?}"
    );
    assert!(matches!(still_waitable, Ok(Some(7))), "{still_waitable:?}");
    assert_eq!(final_result, Progress::Complete(7));
}
