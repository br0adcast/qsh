use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn control_server_rejects_peer_before_read_or_dispatch() {
    for retrieval_error in [false, true] {
        for request in [
            None,
            Some(ControlRequest::Status),
            Some(ControlRequest::AddClient([7; 32])),
            Some(ControlRequest::AddPort(60001)),
            Some(ControlRequest::Stop),
        ] {
            let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
            if let Some(request) = &request {
                client
                    .write_all(control::format_request(request).as_bytes())
                    .await
                    .unwrap();
            }
            let allowlist = Arc::new(std::sync::Mutex::new(Vec::new()));
            let (stop, mut receiver) = mpsc::channel(1);
            let result = handle_transport_control_connection_with_peer_check(
                server,
                allowlist.clone(),
                vec![60000],
                stop,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(tokio::sync::RwLock::new(())),
                None,
                tokio::time::Instant::now() + Duration::from_millis(50),
                |stream| {
                    let actual = control::peer_uid(stream)?;
                    if retrieval_error {
                        control::require_same_account(
                            Err(std::io::Error::from_raw_os_error(libc::EIO)),
                            actual,
                        )
                    } else {
                        control::require_same_account(Ok(actual), actual.wrapping_add(1))
                    }
                },
            )
            .await;
            assert!(result.is_err());
            assert!(
                format!("{:#}", result.unwrap_err()).contains("control peer"),
                "must reject before request timeout"
            );
            assert!(allowlist.lock().unwrap().is_empty());
            assert!(receiver.try_recv().is_err());
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut bytes))
                .await
                .unwrap();
            assert!(
                read.is_ok() || read.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
            );
            assert!(bytes.is_empty());
        }
    }
}

#[tokio::test]
async fn control_peer_same_account_handler_uses_kernel_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("control")).unwrap();
    let mut client = tokio::net::UnixStream::connect(dir.path().join("control"))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    assert_eq!(
        control::peer_uid(&server).unwrap(),
        nix::unistd::geteuid().as_raw()
    );
    let allowlist = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (stop, _receiver) = mpsc::channel(1);
    client
        .write_all(control::format_request(&ControlRequest::AddClient([7; 32])).as_bytes())
        .await
        .unwrap();
    handle_transport_control_connection(
        server,
        allowlist.clone(),
        vec![60000],
        stop,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::RwLock::new(())),
        None,
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    StatusResponse::from_line(std::str::from_utf8(&response).unwrap().trim_end()).unwrap();
    assert_eq!(*allowlist.lock().unwrap(), vec![[7; 32]]);
}

async fn rejected_real_peer(server: tokio::net::UnixStream) {
    // Wait for the owned sender to queue its complete small command. Otherwise
    // successful early rejection could race its write and produce BrokenPipe
    // rather than demonstrate that an already-queued command is not dispatched.
    tokio::time::timeout(Duration::from_secs(4), server.readable())
        .await
        .unwrap()
        .unwrap();
    let allowlist = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (stop, mut receiver) = mpsc::channel(1);
    let result = handle_transport_control_connection(
        server,
        allowlist.clone(),
        vec![60000],
        stop,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::RwLock::new(())),
        None,
        tokio::time::Instant::now() + Duration::from_secs(4),
    )
    .await;
    assert!(format!("{:#}", result.unwrap_err()).contains("control peer"));
    assert!(allowlist.lock().unwrap().is_empty());
    assert!(receiver.try_recv().is_err());
}

fn rejected_request_bytes(request: &ControlRequest) -> Vec<u8> {
    use std::io::{Read, Write};
    // This helper is only used in the foreign self-exec client role.
    let (_, path) = crate::control::peer_fixture::child_role().unwrap();
    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    stream
        .write_all(control::format_request(request).as_bytes())
        .unwrap();
    let mut bytes = Vec::new();
    let result = stream.read_to_end(&mut bytes);
    assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
    bytes
}

#[tokio::test]
async fn control_peer_root_server_rejects_foreign_client() {
    use crate::control::peer_fixture::{self, Fixture};
    const NAME: &str =
        "transport_daemon::peer_tests::control_peer_root_server_rejects_foreign_client";
    if let Some((role, _path)) = peer_fixture::child_role() {
        let request = match role.as_str() {
            "add-client" => ControlRequest::AddClient([7; 32]),
            "add-port" => ControlRequest::AddPort(60001),
            "stop" => ControlRequest::Stop,
            _ => panic!("unexpected owned child role"),
        };
        assert!(rejected_request_bytes(&request).is_empty());
        return;
    }
    if !peer_fixture::enabled(NAME) {
        return;
    }
    for role in ["add-client", "add-port", "stop"] {
        let mut fixture = Fixture::new();
        let listener = std::os::unix::net::UnixListener::bind(&fixture.path).unwrap();
        peer_fixture::allow_fixture_connection(&fixture.path);
        fixture.spawn(NAME, role);
        let server = peer_fixture::accept(&listener, fixture.deadline);
        assert_eq!(control::peer_uid(&server).unwrap(), peer_fixture::FOREIGN);
        server.set_nonblocking(true).unwrap();
        rejected_real_peer(tokio::net::UnixStream::from_std(server).unwrap()).await;
        fixture.finish();
    }
}

#[tokio::test]
async fn control_peer_foreign_server_rejects_root_client() {
    use crate::control::peer_fixture::{self, Fixture};
    const NAME: &str =
        "transport_daemon::peer_tests::control_peer_foreign_server_rejects_root_client";
    if let Some((role, path)) = peer_fixture::child_role() {
        assert_eq!(role, "server");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        peer_fixture::allow_fixture_connection(&path);
        let server = peer_fixture::accept(
            &listener,
            std::time::Instant::now() + Duration::from_secs(4),
        );
        assert_eq!(control::peer_uid(&server).unwrap(), 0);
        server.set_nonblocking(true).unwrap();
        rejected_real_peer(tokio::net::UnixStream::from_std(server).unwrap()).await;
        return;
    }
    if !peer_fixture::enabled(NAME) {
        return;
    }
    for request in [
        ControlRequest::AddClient([7; 32]),
        ControlRequest::AddPort(60001),
        ControlRequest::Stop,
    ] {
        let mut fixture = Fixture::new();
        fixture.spawn(NAME, "server");
        fixture.wait_for_socket();
        let mut stream = std::os::unix::net::UnixStream::connect(&fixture.path).unwrap();
        use std::io::{Read, Write};
        stream.set_read_timeout(Some(fixture.remaining())).unwrap();
        stream
            .write_all(control::format_request(&request).as_bytes())
            .unwrap();
        let mut bytes = Vec::new();
        let result = stream.read_to_end(&mut bytes);
        assert!(
            result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
        );
        assert!(bytes.is_empty());
        fixture.finish();
    }
}
