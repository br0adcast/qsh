use crate::channel::{
    encode_server, About, ActiveChannel, ChannelKind, ChannelSnapshot, DaemonMode, DrainingChannel,
    OpenClassification, OpenRequest, RejectCode, ServerRecord, UpdateAnswer, UpdateResult,
    CHANNEL_IDENTITIES, FIRST_CHANNEL_STREAM, MAX_ARCH_LEN, MAX_COMMAND_LEN, PROTOCOL_VERSION,
};
use crate::channel_geometry::ChannelInstance;

#[test]
fn envelope_wire_maxima_cover_complete_records_and_mandatory_update_sequence() {
    assert_eq!(SESSION_BYTES, 764_600);
    assert_eq!(GLOBAL_BYTES, 97_868_800);
    let about = encode_server(&ServerRecord::About(About {
        build: u64::MAX,
        checksum: [0; 32],
        arch: "a".repeat(MAX_ARCH_LEN),
        protocol: PROTOCOL_VERSION,
        mode: DaemonMode::Personal,
    }));
    assert_eq!(about.len(), 80);
    let refused = encode_server(&ServerRecord::Refused {
        stream: 16,
        reason: "r".repeat(CONTROL_RECORD_MAX - 1),
    });
    assert_eq!(refused.len(), MAX_RECORD);
    let result = encode_server(&ServerRecord::UpdateResult(UpdateResult::Rejected {
        code: RejectCode::Other,
        detail: "r".repeat(CONTROL_RECORD_MAX - 2),
    }));
    assert_eq!(result.len(), MAX_RECORD);
    let accept = encode_server(&ServerRecord::UpdateAnswer(UpdateAnswer::Accept));
    let restarting = encode_server(&ServerRecord::UpdateResult(UpdateResult::Restarting));
    assert_eq!(
        accept.len() + restarting.len() + result.len(),
        UPDATE_ENVELOPE
    );
    assert_eq!(
        encode_server(&ServerRecord::UpdateAnswer(UpdateAnswer::Busy {
            others: u32::MAX
        }))
        .len(),
        10
    );
    assert_eq!(encode_server(&ServerRecord::Opened { stream: 16 }).len(), 6);
    assert_eq!(
        encode_server(&ServerRecord::Exit {
            stream: 16,
            code: i32::MAX
        })
        .len(),
        10
    );
    assert_eq!(
        encode_server(&ServerRecord::ExitStatusUnavailable { stream: 16 }).len(),
        6
    );
    assert_eq!(encode_server(&ServerRecord::Restarting).len(), 5);
}

#[test]
fn snapshot_envelope_covers_maximum_active_commands_and_every_other_draining_identity() {
    let mut active = Vec::new();
    for index in 0..MAX_CHANNELS {
        active.push(ActiveChannel {
            instance: ChannelInstance::new(index as u64 + 1).unwrap(),
            request: OpenRequest {
                stream: FIRST_CHANNEL_STREAM + index as u8,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: vec![b'c'; MAX_COMMAND_LEN],
            },
        });
    }
    let mut draining = Vec::new();
    for index in MAX_CHANNELS..CHANNEL_IDENTITIES {
        draining.push(DrainingChannel {
            stream: (FIRST_CHANNEL_STREAM as usize + index) as u8,
            instance: ChannelInstance::new(index as u64 + 1).unwrap(),
            open: OpenClassification {
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
            },
        });
    }
    let snapshot = ChannelSnapshot::new(active, draining).unwrap();
    assert_eq!(
        encode_server(&ServerRecord::ChannelSnapshot(snapshot)).len(),
        MAX_SNAPSHOT
    );
    assert_eq!(MAX_SNAPSHOT, 36_391);
}
