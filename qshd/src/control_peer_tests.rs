use super::*;
use std::io::Read;

#[test]
fn control_peer_account_policy_has_no_root_or_group_bypass() {
    for (peer, expected, accepted) in [
        (1000, 1000, true),
        (0, 0, true),
        (0, 1000, false),
        (1000, 0, false),
        (1001, 1000, false),
    ] {
        assert_eq!(require_same_account(Ok(peer), expected).is_ok(), accepted);
    }
    assert!(require_same_account(Err(std::io::Error::from_raw_os_error(libc::EIO)), 1000).is_err());
}

#[test]
fn control_peer_same_account_uses_kernel_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control");
    let listener = UnixListener::bind(&path).unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        assert_eq!(peer_uid(stream).unwrap(), nix::unistd::geteuid().as_raw());
        check_control_peer(stream).unwrap();
    }
}

#[test]
fn control_client_rejects_peer_before_sending_request() {
    for retrieval_error in [false, true] {
        for request in [
            ControlRequest::Status,
            ControlRequest::AddClient([7; 32]),
            ControlRequest::Stop,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("control");
            let listener = UnixListener::bind(&path).unwrap();
            let observer = std::thread::spawn(move || {
                // The client connects synchronously before applying the seam.
                let mut stream = super::peer_fixture::accept(
                    &listener,
                    std::time::Instant::now() + Duration::from_secs(2),
                );
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).unwrap();
                bytes
            });
            let result = client_request_with_peer_check(
                &path,
                &request,
                Duration::from_millis(50),
                |stream| {
                    let actual = peer_uid(stream)?;
                    if retrieval_error {
                        require_same_account(
                            Err(std::io::Error::from_raw_os_error(libc::EIO)),
                            actual,
                        )
                    } else {
                        require_same_account(Ok(actual), actual.wrapping_add(1))
                    }
                },
            );
            let bytes = observer.join().unwrap();
            assert!(
                result.is_err(),
                "credential failure must be a hard error: {result:?}"
            );
            assert!(bytes.is_empty(), "a rejected server received request bytes");
        }
    }
}

#[test]
fn control_peer_root_client_rejects_foreign_server() {
    use super::peer_fixture::{self, Fixture};
    const NAME: &str = "control::peer_tests::control_peer_root_client_rejects_foreign_server";
    if let Some((role, path)) = peer_fixture::child_role() {
        assert_eq!(role, "server");
        let listener = UnixListener::bind(&path).unwrap();
        peer_fixture::allow_fixture_connection(&path);
        let mut stream = peer_fixture::accept(
            &listener,
            std::time::Instant::now() + Duration::from_secs(4),
        );
        assert_eq!(peer_uid(&stream).unwrap(), 0);
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty(), "foreign server received a request");
        return;
    }
    if !peer_fixture::enabled(NAME) {
        return;
    }
    let mut fixture = Fixture::new();
    fixture.spawn(NAME, "server");
    fixture.wait_for_socket();
    let result =
        client_request_with_timeout(&fixture.path, &ControlRequest::Status, fixture.remaining());
    fixture.finish();
    assert!(format!("{:#}", result.unwrap_err()).contains("control peer"));
}

#[test]
fn control_peer_foreign_client_rejects_root_server() {
    use super::peer_fixture::{self, Fixture};
    const NAME: &str = "control::peer_tests::control_peer_foreign_client_rejects_root_server";
    if let Some((role, path)) = peer_fixture::child_role() {
        assert_eq!(role, "client");
        let error =
            client_request_with_timeout(&path, &ControlRequest::Status, Duration::from_secs(4))
                .unwrap_err();
        assert!(format!("{error:#}").contains("control peer"));
        return;
    }
    if !peer_fixture::enabled(NAME) {
        return;
    }
    let mut fixture = Fixture::new();
    let listener = UnixListener::bind(&fixture.path).unwrap();
    peer_fixture::allow_fixture_connection(&fixture.path);
    fixture.spawn(NAME, "client");
    let mut stream = peer_fixture::accept(&listener, fixture.deadline);
    assert_eq!(peer_uid(&stream).unwrap(), peer_fixture::FOREIGN);
    stream.set_read_timeout(Some(fixture.remaining())).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    fixture.finish();
    assert!(bytes.is_empty(), "root server received a request");
}
