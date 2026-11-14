//! One destructive dispatch owns one checked connection and never retries it.
use super::*;
use std::io::Read;

#[test]
fn service_stop_requires_exact_ack_and_never_retries_lost_or_malformed_replies() {
    for (reply, expected) in [
        (
            &b"{\"stopped\":true}\n"[..],
            ServiceStopDispatch::Acknowledged,
        ),
        (
            &b"{\"stopping\":true}\n"[..],
            ServiceStopDispatch::Acknowledged,
        ),
        (
            &b"{\"stopping\":false}\n"[..],
            ServiceStopDispatch::Uncertain,
        ),
        (
            &b"{\"stopped\":true,\"stopping\":true}\n"[..],
            ServiceStopDispatch::Uncertain,
        ),
        (&b""[..], ServiceStopDispatch::Uncertain),
        (
            &b"{\"stopped\":false}\n"[..],
            ServiceStopDispatch::Uncertain,
        ),
        (&b"malformed\n"[..], ServiceStopDispatch::Uncertain),
        (
            &b"{\"stopped\":true,\"extra\":1}\n"[..],
            ServiceStopDispatch::Uncertain,
        ),
    ] {
        let directory = private_test_dir().unwrap();
        let endpoint = directory.path().join("control.sock");
        let transaction = EnsureLock::acquire(&endpoint, Duration::from_secs(1)).unwrap();
        let listener = UnixListener::bind(&endpoint).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            stream.write_all(reply).unwrap();
            listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            request
        });
        assert_eq!(transaction.stop_service_once(), expected);
        assert_eq!(server.join().unwrap(), "STOP\n");
    }
}

#[test]
fn service_stop_refuses_absent_route_and_wrong_peer_before_sending_bytes() {
    let directory = private_test_dir().unwrap();
    let endpoint = directory.path().join("control.sock");
    let transaction = EnsureLock::acquire(&endpoint, Duration::from_secs(1)).unwrap();
    assert_eq!(
        transaction.stop_service_once(),
        ServiceStopDispatch::Refused
    );
    let listener = UnixListener::bind(&endpoint).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        request
    });
    assert_eq!(
        transaction.stop_service_once_checked(Duration::from_millis(20), |stream| {
            require_same_account(
                peer_uid(stream),
                nix::unistd::geteuid().as_raw().wrapping_add(1),
            )
        }),
        ServiceStopDispatch::Refused
    );
    assert!(server.join().unwrap().is_empty());
}

#[test]
fn service_stop_timeout_after_write_is_uncertain() {
    let directory = private_test_dir().unwrap();
    let endpoint = directory.path().join("control.sock");
    let transaction = EnsureLock::acquire(&endpoint, Duration::from_secs(1)).unwrap();
    let listener = UnixListener::bind(&endpoint).unwrap();
    let (release, hold) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();
        let mut request = String::new();
        stream.read_to_string(&mut request).unwrap();
        hold.recv_timeout(Duration::from_secs(2)).unwrap();
        request
    });
    assert_eq!(
        transaction.stop_service_once_checked(Duration::from_millis(20), check_control_peer),
        ServiceStopDispatch::Uncertain
    );
    release.send(()).unwrap();
    assert_eq!(server.join().unwrap(), "STOP\n");
}
