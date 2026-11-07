// Included in manager tests to observe the actual admission/resource tables.
#[tokio::test]
async fn bootstrap_manager_dispatch_never_admits_or_issues_auth_nonce() {
    use crate::bootstrap::{BootstrapClient, BootstrapResponder, ServerInfo};
    struct NoNonce;
    impl NonceSource for NoNonce {
        fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
            panic!("metadata must not issue authentication nonce")
        }
        fn release(&self, _nonce: [u8; AUTH_NONCE_LEN]) {
            panic!("metadata must not release authentication nonce")
        }
    }
    let token = [4; 16];
    let (mut wiring, _) = RouterWiring::new(HelperLogins::with(token)).await;
    wiring.auth.nonces = Arc::new(NoNonce);
    let mut router = Router::new();
    let info = ServerInfo {
        generation: [7; 16],
        core_version: "0.6.0".into(),
        session_protocols: vec![],
    };
    router.server_generation = Some(info.generation);
    router.bootstrap = Some(BootstrapResponder::new(wiring.server_priv, info.clone()).unwrap());
    let local = generate_keypair();
    let mut client = BootstrapClient::new(local.private, wiring.server_pub, [5; 32]);
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let src = source.local_addr().unwrap();
    let mut buf = [0; 512];
    for turn in 0..2 {
        let request = client.request();
        SessionManager::handle_datagram(&wiring.ctx(), &mut router, request.len(), src, &request)
            .await;
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), source.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        if turn == 0 {
            assert_eq!(
                client.accept(&buf[..len]),
                Err(crate::bootstrap::BootstrapError::Retry)
            );
        } else {
            assert_eq!(client.accept(&buf[..len]).unwrap().info(), &info);
        }
    }
    assert!(router.sessions.is_empty());
    assert!(router.backends.is_empty());
    assert!(router.probation.is_empty());
    assert!(router.retiring.is_empty());
    assert!(wiring.auth.allowlist.lock().unwrap().is_empty());
    assert_eq!(wiring.active_count.load(Ordering::SeqCst), 0);
}
