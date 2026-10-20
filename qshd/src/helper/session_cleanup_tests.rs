#[test]
fn pam40_session_cleanup_retains_delete_failure_and_partial_open_obligations() {
    let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
        "helper::monitor::tests::pam40_session_cleanup_retains_delete_failure_and_partial_open_obligations_body",
    );
    assert!(
        status.success(),
        "owned Session control failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[ignore = "runs only in the owned Session cleanup subprocess"]
fn pam40_session_cleanup_retains_delete_failure_and_partial_open_obligations_body() {
    fn test_groups() -> nix::Result<Vec<Gid>> {
        let user = nix::unistd::User::from_uid(Uid::current())
            .unwrap()
            .unwrap();
        Ok(super::super::account::lookup(&user.name).unwrap().groups)
    }
    let user = nix::unistd::User::from_uid(Uid::current())
        .unwrap()
        .unwrap();
    let account = super::super::account::lookup(&user.name).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (service, session_module) in [("complete", "pam_permit.so"), ("partial", "pam_deny.so")] {
        std::fs::write(dir.path().join(service), format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required {session_module}\n")).unwrap();
    }
    let plan = |service: &str| MonitorPlan {
        account: account.clone(),
        login: [40; 16],
        tty: "/dev/pts/0".into(),
        rhost: "203.0.113.7:1234".into(),
        pam_service: service.into(),
        pam_confdir: Some(dir.path().into()),
        become_account: |_, _, _| Ok(()),
        session_group_ops: SessionGroupOps {
            install: |_| Ok(()),
            capture: test_groups,
        },
        fd_limit: 0,
        session_budget: Duration::from_secs(2),
        session_close_budget: Duration::from_secs(2),
    };
    let mut complete_steps = Vec::new();
    let complete = Session::begin(&plan("complete")).unwrap();
    let complete_result = complete.close_using(|pam, step| {
        complete_steps.push(step);
        let result = native_cleanup_step(pam, step);
        assert_eq!(result, PamStep::Attempted(0));
        if step == CleanupStep::DeleteCred {
            PamStep::Attempted(17)
        } else {
            result
        }
    });
    let mut partial_steps = Vec::new();
    let partial = match Session::begin_using(&plan("partial"), |session| {
        session.close_using(|pam, step| {
            partial_steps.push(step);
            let result = native_cleanup_step(pam, step);
            assert_eq!(result, PamStep::Attempted(0));
            if step == CleanupStep::DeleteCred {
                PamStep::Attempted(17)
            } else {
                result
            }
        })
    }) {
        Ok(session) => {
            session.close();
            panic!("deny stack must refuse real session open")
        }
        Err(failure) => failure,
    };
    assert_eq!(
        complete_steps,
        [
            CleanupStep::CloseSession,
            CleanupStep::DeleteCred,
            CleanupStep::End
        ]
    );
    assert_eq!(partial_steps, [CleanupStep::DeleteCred, CleanupStep::End]);
    assert!(
        partial.why.contains("pam_open_session"),
        "original refusal retained: {}",
        partial.why
    );
    assert_eq!(
        complete_result,
        PamCompletion::Finished {
            close_session: PamStep::Attempted(0),
            delete_cred: PamStep::Attempted(17),
            end: PamStep::Attempted(0)
        }
    );
    assert_eq!(
        partial.cleanup,
        PamCompletion::Finished {
            close_session: PamStep::Skipped,
            delete_cred: PamStep::Attempted(17),
            end: PamStep::Attempted(0)
        }
    );
    assert!(!complete_result.succeeded());
    assert!(!partial.cleanup.succeeded());
}
