// Included in server::tests to exercise the actual helper poll loop.
#[test]
fn diagnostic_flood_and_eof_preserve_authentication_and_channel_progress() {
    let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();
    let (sender, receiver) = crate::log::relay::pair().unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Fill the queue before the helper starts; saturation is observed, not inferred.
    let mut queued = 0;
    while sender.report(crate::log::Level::Info, "worker", "flood") {
        queued += 1;
        assert!(queued < 10000, "the diagnostic queue must be bounded");
    }
    assert!(queued > 0);
    let flooder = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(AtomicOrdering::Relaxed) {
                sender.report(crate::log::Level::Info, "worker", "flood");
                std::thread::yield_now();
            }
        })
    };
    let helper = std::thread::spawn(move || {
        serve(
            helper_channels,
            helper_auth,
            test_config(),
            HashMap::new(),
            UNPRIVILEGED,
            Some(receiver),
        );
    });
    struct Fixture {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        flooder: Option<JoinHandle<()>>,
        helper: Option<JoinHandle<()>>,
        channels: UnixStream,
        auth: UnixStream,
    }
    impl Fixture {
        fn end_diagnostics(&mut self) {
            self.stop.store(true, AtomicOrdering::Relaxed);
            if let Some(flooder) = self.flooder.take() {
                join_within(flooder, "nonblocking diagnostic sender must stop");
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.end_diagnostics();
            let _ = self.channels.shutdown(std::net::Shutdown::Both);
            let _ = self.auth.shutdown(std::net::Shutdown::Both);
            if let Some(helper) = self.helper.take() {
                join_within(helper, "diagnostic EOF must not keep the helper alive");
            }
        }
    }
    let mut fixture = Fixture {
        stop,
        flooder: Some(flooder),
        helper: Some(helper),
        channels,
        auth,
    };
    assert!(matches!(
        ask(&fixture.auth, Request::Nonce),
        Response::Nonce { .. }
    ));
    let request = Request::Open {
        id: 1,
        uid: me_uid(),
        name: my_login(),
        login: [0; 16],
        cols: 80,
        rows: 24,
        term: None,
        echo: true,
        shell: true,
        command: String::new(),
    };
    super::channel::send(&fixture.channels, &encode(&request).unwrap(), None).unwrap();
    assert!(matches!(
        next_response(&fixture.channels),
        (Response::Failed { id: 1, .. }, None)
    ));
    // Actual EOF reaches the helper while both functional seams remain open.
    fixture.end_diagnostics();
    assert!(matches!(
        ask(&fixture.auth, Request::Nonce),
        Response::Nonce { .. }
    ));
}
