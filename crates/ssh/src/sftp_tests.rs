use super::*;
use bytes::Bytes;
use russh_sftp::protocol::{Handle, Packet, Status, StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[derive(Default)]
struct CapturedRequests(Vec<u64>);
impl RequestBarrier for CapturedRequests {
    async fn wait<T>(
        &mut self,
        bytes: u64,
        reply: impl Future<Output = Result<T, SshError>>,
    ) -> Result<T, SshError> {
        self.0.push(bytes);
        reply.await
    }
}
struct Progress(Mutex<Vec<(u64, u64)>>);
impl UploadProgress for Progress {
    fn uploaded(&self, bytes: u64, total: u64) {
        self.0.lock().unwrap().push((bytes, total));
    }
}
async fn read_packet(peer: &mut DuplexStream) -> (Packet, Vec<u8>) {
    let length = peer.read_u32().await.unwrap() as usize;
    assert!(length <= PACKET as usize);
    let mut payload = vec![0; length];
    peer.read_exact(&mut payload).await.unwrap();
    let packet = Packet::try_from(&mut Bytes::copy_from_slice(&payload)).unwrap();
    (packet, payload)
}
async fn reply(peer: &mut DuplexStream, packet: Packet) {
    let bytes = Bytes::try_from(packet).unwrap();
    peer.write_all(&bytes).await.unwrap();
}
fn ok(id: u32) -> Packet {
    Packet::Status(Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    })
}

#[tokio::test]
async fn transfer_serializes_private_exclusive_open_before_writing() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let path = "/owned/qshd.tmp";
        let body = b"owned inert bytes";
        let (stream, mut peer) = tokio::io::duplex(PACKET as usize);
        let session = RawSftpSession::new(stream);
        let cancel = knock::Cancel::new();
        let mut clock = Clock {
            start: Instant::now(),
            last: Instant::now(),
            limits: TransferLimits {
                total: Duration::from_secs(4),
                idle: Duration::from_secs(4),
                max_bytes: 1024,
            },
            cancel: &cancel,
        };
        let progress = Progress(Mutex::default());
        let mut requests = CapturedRequests::default();
        let server = async {
            let (init, _) = read_packet(&mut peer).await;
            assert!(matches!(init, Packet::Init(_)));
            reply(&mut peer, Packet::Version(Version::new())).await;
            let (packet, payload) = read_packet(&mut peer).await;
            let Packet::Open(open) = packet else {
                panic!("expected OPEN before WRITE")
            };
            assert_eq!(open.filename, path);
            assert_eq!(
                open.pflags.bits(),
                (OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE).bits()
            );
            assert_eq!(open.attrs.permissions, Some(0o600));
            assert_eq!(payload.len() + 4, path.len() + 25);
            // Decode the actual attribute flags rather than infer their presence
            // from a helper value. PERMISSIONS is the only requested attribute.
            let attr_flags = 1 + 4 + 4 + path.len() + 4;
            assert_eq!(&payload[attr_flags..attr_flags + 4], &4_u32.to_be_bytes());
            assert_eq!(
                &payload[attr_flags + 4..attr_flags + 8],
                &0o600_u32.to_be_bytes()
            );
            reply(
                &mut peer,
                Packet::Handle(Handle {
                    id: open.id,
                    handle: "owned-handle".into(),
                }),
            )
            .await;
            let (write, _) = read_packet(&mut peer).await;
            let Packet::Write(write) = write else {
                panic!("expected WRITE")
            };
            assert_eq!(write.handle, "owned-handle");
            assert_eq!(write.offset, 0);
            assert_eq!(write.data, body);
            reply(&mut peer, ok(write.id)).await;
            let (close, _) = read_packet(&mut peer).await;
            let Packet::Close(close) = close else {
                panic!("expected CLOSE")
            };
            assert_eq!(close.handle, "owned-handle");
            reply(&mut peer, ok(close.id)).await;
            // Keep the stream alive until transfer consumes its final reply.
            peer
        };
        let (result, _peer) = tokio::join!(
            transfer(&session, path, body, &progress, &mut clock, &mut requests),
            server
        );
        result.unwrap();
        assert_eq!(
            requests.0,
            vec![
                9,
                path.len() as u64 + 25,
                body.len() as u64 + "owned-handle".len() as u64 + 25,
                "owned-handle".len() as u64 + 13
            ]
        );
        assert_eq!(
            *progress.0.lock().unwrap(),
            vec![(body.len() as u64, body.len() as u64)]
        );
        session.close_session().unwrap();
    })
    .await
    .expect("in-memory transfer exceeded bound");
}
