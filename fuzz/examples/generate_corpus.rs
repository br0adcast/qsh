//! Regenerate every synthetic, encoder-derived seed directory.
use std::path::Path;

type Cases = Vec<(&'static str, Vec<u8>)>;
type Targets = [(&'static str, Cases); 6];

fn main() -> std::io::Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .expect("explicit owned output directory required");
    let output = Path::new(&output);
    let targets: Targets = [
        ("channel_codec", qsh_channel_fuzz::seeds::cases()),
        ("handshake_payload", qsh_channel_fuzz::handshake::cases()),
        ("wire_datagram", qsh_channel_fuzz::wire::cases()),
        ("deframer", qsh_channel_fuzz::deframe::cases()),
        ("authorized_keys", qsh_channel_fuzz::auth_keys::cases()),
        ("terminal_feed_resize", qsh_channel_fuzz::terminal::cases()),
    ];
    for (target, cases) in targets {
        let directory = output.join(target);
        std::fs::create_dir_all(&directory)?;
        for (name, bytes) in cases {
            std::fs::write(directory.join(name), bytes)?;
        }
    }
    Ok(())
}
