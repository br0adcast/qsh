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
                Ok(None) => {
                    let _ = self.child.kill();
                }
                Err(error) => eprintln!(
                    "owned gate fixture observation failed; retaining exact child: {error}"
                ),
            }
            let mut reported = false;
            loop {
                match self.child.wait() {
                    Ok(_) => return,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        if !reported {
                            eprintln!(
                                "owned gate fixture wait failed; retaining exact child: {error}"
                            );
                            reported = true;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
    }
    fn finish_before(
        scope: &mut Scope<ForkChild>,
        deadline: Instant,
        mut pending: impl FnMut(&Scope<ForkChild>),
    ) -> Progress {
        loop {
            assert!(
                Instant::now() < deadline,
                "native final-reap fixture exceeded its shared deadline"
            );
            let result = scope.step(&mut Native);
            if result != Progress::Pending {
                return result;
            }
            pending(scope);
            // Only a later actual Complete permits success; pacing is not proof.
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    // Both native subcases share the fixture's existing total bound.
    let deadline = Instant::now() + Duration::from_secs(2);
    for deferred in [false, true] {
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
        let exited = loop {
            match child.observe() {
                Ok(Some(7)) => break true,
                Ok(None) => {}
                other => panic!("exact native fixture exit observation failed: {other:?}"),
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut scope = Scope::new(child, view);
        scope.request_stop();
        let held: Vec<_> = if deferred {
            (0..3)
                .map(|_| scope.step_without_reap(&mut Native))
                .collect()
        } else {
            Vec::new()
        };
        // This independent observation is WNOWAIT only: it never competes with the
        // retained scope's consuming wait. A latched synthetic code cannot satisfy it.
        let still_waitable = ForkChild::new(pid).observe();
        let mut first_pending = None;
        let final_result = finish_before(&mut scope, deadline, |scope| {
            if !deferred && first_pending.is_none() {
                // An empty scope's first native capture must retain the real
                // leader and request a fresh census before any consuming wait.
                assert_eq!(scope.members.len(), 1);
                assert_eq!(scope.members[0].pid, pid.get());
                first_pending = Some(ForkChild::new(pid).observe());
            }
        });
        fixture.reaped = matches!(final_result, Progress::Complete(_));
        drop(fixture); // every failure still retains and waits only this exact child
        assert!(exited, "deadline is failure, never exit proof");
        assert!(
            held.iter().all(|progress| *progress == Progress::Pending),
            "{held:?}"
        );
        assert!(matches!(still_waitable, Ok(Some(7))), "{still_waitable:?}");
        if !deferred {
            assert!(
                matches!(first_pending, Some(Ok(Some(7)))),
                "{first_pending:?}"
            );
            println!("validated real native first Pending and preserved waitable leader");
        }
        assert_eq!(final_result, Progress::Complete(7), "deferred={deferred}");
    }
}
