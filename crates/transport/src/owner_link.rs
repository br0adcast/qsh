//! The frontend/owner link: a bounded wire codec for the Unix socketpair that
//! joins a network frontend to a session owner process (#529 M1). This module
//! only defines the messages and their framing; custody objects never cross it
//! (they are represented by owner queue positions, `u64` ids).

// Nothing uses the codec until the owner process is wired in.
#[allow(dead_code)]
#[path = "owner_link_codec.rs"]
pub(crate) mod codec;
#[cfg(test)]
#[path = "owner_link_codec_tests.rs"]
mod codec_tests;
