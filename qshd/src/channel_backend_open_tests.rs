// Included in channel_backend::tests; all failures exercise the production assembly path.
mod open24_tests {
    use super::*;
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;
    use portable_pty::MasterPty;

    struct FailingMaster {
        inner: Box<dyn MasterPty + Send>,
        reader: bool,
    }

    impl MasterPty for FailingMaster {
        fn resize(&self, size: PtySize) -> anyhow::Result<()> {
            self.inner.resize(size)
        }
        fn get_size(&self) -> anyhow::Result<PtySize> {
            self.inner.get_size()
        }
        fn try_clone_reader(&self) -> anyhow::Result<Box<dyn Read + Send>> {
            if self.reader {
                anyhow::bail!("injected reader preparation failure");
            }
            self.inner.try_clone_reader()
        }
        fn take_writer(&self) -> anyhow::Result<Box<dyn Write + Send>> {
            anyhow::bail!("injected writer preparation failure")
        }
        fn process_group_leader(&self) -> Option<i32> {
            self.inner.process_group_leader()
        }
        fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
            self.inner.as_raw_fd()
        }
        fn tty_name(&self) -> Option<std::path::PathBuf> {
            self.inner.tty_name()
        }
    }

    // The fixture owns this exact, unreaped direct child independently of product custody.
    // Once waitpid says ECHILD it must never signal that numeric pid again.
    struct ReapFixture(Pid);
    impl Drop for ReapFixture {
        fn drop(&mut self) {
            match waitpid(self.0, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    let _ = kill(self.0, Signal::SIGKILL);
                    loop {
                        match waitpid(self.0, None) {
                            Err(Errno::EINTR) => continue,
                            Ok(_) | Err(Errno::ECHILD) => break,
                            Err(error) => panic!("fixture child wait failed: {error}"),
                        }
                    }
                }
                Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(Errno::ECHILD) => {}
                other => panic!("unexpected fixture wait result: {other:?}"),
            }
        }
    }

    fn preparation_failure_reaps(reader: bool) {
        suppress_shell_history();
        let budget = budget();
        let mut req = request(ChannelKind::Command, 80, 24, b"/bin/sleep 60");
        req.screen = true;
        let screen = make_screen(&req, &owner(), budget.clone()).unwrap();
        let (master, child) = pty::spawn_command_no_echo(
            PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            },
            command_builder(&req.command).unwrap(),
            None,
        )
        .unwrap();
        let pid = Pid::from_raw(child.process_id().unwrap() as i32);
        let fixture = ReapFixture(pid);
        let custody = OpenCustody::new();
        let outcome = finish_personal_spawn(
            Box::new(FailingMaster {
                inner: master,
                reader,
            }),
            child,
            screen,
            &custody,
        );
        assert!(
            outcome.is_err(),
            "the requested descriptor failure must occur"
        );
        assert!(matches!(
            custody.cleanup(),
            transport::channel_open::CleanupStatus::Confirmed(_)
        ));
        let result = waitpid(pid, Some(WaitPidFlag::WNOHANG));
        // ReapFixture also handles the RED path before the assertion unwinds.
        let reaped_by_product = result == Err(Errno::ECHILD);
        drop(fixture);
        assert!(
            reaped_by_product,
            "descriptor preparation returned without reaping its child: {result:?}"
        );
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
    }

    #[test]
    fn open24_reader_setup_failure_reaps_child() {
        preparation_failure_reaps(true);
    }

    #[test]
    fn open24_writer_setup_failure_reaps_child() {
        preparation_failure_reaps(false);
    }
}
