//! Synthetic public protocol examples; no recorded traffic or credentials.
use transport::{
    channel::*,
    channel_geometry::{ChannelInstance, ResizeRequestId},
};

fn input(envelope: Vec<u8>) -> Vec<u8> {
    assert!(envelope.len() >= 5);
    let mut out = vec![envelope[0]];
    out.extend_from_slice(&envelope[5..]);
    out
}

pub fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let open = |stream, command| OpenRequest {
        stream,
        kind: ChannelKind::Command,
        cols: 80,
        rows: 24,
        screen: false,
        command,
    };
    let client = |record| input(encode_client(&record));
    let server = |record| input(encode_server(&record));
    let about = About {
        build: 1,
        checksum: [0; 32],
        arch: "x86_64".into(),
        protocol: PROTOCOL_VERSION,
        mode: DaemonMode::Personal,
    };
    let full_about = server(ServerRecord::About(about));
    let mut extended_about = full_about.clone();
    extended_about.extend_from_slice(&[0xa5, 0x5a]);
    let mut short_about = full_about.clone();
    short_about.truncate(short_about.len() - 2);
    let max_snapshot = ChannelSnapshot::new(
        (0..MAX_CHANNELS as u8)
            .map(|i| ActiveChannel {
                instance: ChannelInstance::new(u64::from(i) + 1).unwrap(),
                request: open(FIRST_CHANNEL_STREAM + i, vec![b'c'; MAX_COMMAND_LEN]),
            })
            .collect(),
        ((FIRST_CHANNEL_STREAM + MAX_CHANNELS as u8)..=u8::MAX)
            .map(|stream| DrainingChannel {
                stream,
                instance: ChannelInstance::new(u64::from(stream) + 1).unwrap(),
                open: OpenClassification {
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: true,
                },
            })
            .collect(),
    )
    .unwrap();
    let max_snapshot = server(ServerRecord::ChannelSnapshot(max_snapshot));
    assert_eq!(max_snapshot.len() - 1, CHANNEL_SNAPSHOT_MAX);
    vec![
        ("empty", vec![]),
        ("unknown", vec![0xff]),
        (
            "shell-open",
            client(ClientRecord::Open(OpenRequest {
                kind: ChannelKind::Shell,
                command: vec![],
                ..open(16, vec![])
            })),
        ),
        (
            "command-max",
            client(ClientRecord::Open(open(17, vec![b'c'; MAX_COMMAND_LEN]))),
        ),
        ("close", client(ClientRecord::Close { stream: 16 })),
        ("term-max", client(ClientRecord::Term("x".repeat(64)))),
        ("resize-zero-ids", {
            let mut input = vec![REC_RESIZE_REQUEST, 16];
            input.extend_from_slice(&[0; 20]);
            input
        }),
        (
            "resize-boundary",
            client(ClientRecord::ResizeRequest {
                stream: 16,
                instance: ChannelInstance::new(1).unwrap(),
                request_id: ResizeRequestId::new(1).unwrap(),
                cols: 0,
                rows: u16::MAX,
            }),
        ),
        ("about-short", short_about),
        ("about-full", full_about),
        ("about-extension", extended_about),
        ("about-request-extension", vec![0x14, 1, 2, 3]),
        (
            "update-offer",
            client(ClientRecord::UpdateOffer(UpdateOffer {
                build: 1,
                checksum: [0; 32],
                arch: "x86_64".into(),
                size: 1,
            })),
        ),
        (
            "update-answer",
            server(ServerRecord::UpdateAnswer(UpdateAnswer::Accept)),
        ),
        (
            "update-result",
            server(ServerRecord::UpdateResult(UpdateResult::Restarting)),
        ),
        (
            "snapshot-empty",
            server(ServerRecord::ChannelSnapshot(
                ChannelSnapshot::new(vec![], vec![]).unwrap(),
            )),
        ),
        ("snapshot-max", max_snapshot),
        ("truncated-open", vec![0x10]),
        ("invalid-utf8-term", vec![0x13, 0xff]),
    ]
}
