//! The transport's negotiable features (spec §5): what a connection may do
//! beyond the format every build since 0.1 speaks, and -- from the
//! negotiation on -- the rule that decides what one connection uses.
//!
//! The set travels as 32 bits in the handshake: msg1 carries what the client
//! offers, msg2 what the server enabled (`crate::handshake_payload`). A peer
//! built before negotiation sends neither field, and reads as offering, or
//! enabling, nothing.

use std::fmt;
use std::ops::{BitAnd, BitOr};

/// A set of transport features; bit 0 is `0x0000_0001`.
///
/// Keeps every bit it was built with, known or not: a newer peer's unknown
/// bits are ignored where they are offered, and read back where they must
/// not appear (a msg2 enabling what msg1 never offered).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Features(u32);

impl Features {
    /// Nothing: the mode of a peer built before negotiation.
    pub const NONE: Features = Features(0);
    /// Bit 0: the 18-byte datagram header is the AEAD's associated data
    /// (spec §4.9).
    pub const HEADER_AAD: Features = Features(1 << 0);
    /// Bit 1: `CREDIT` frames and per-stream limits (spec §6): a slow
    /// consumer holds back only its own stream.
    pub const STREAM_CREDIT: Features = Features(1 << 1);
    /// Bit 2: stream offsets modulo 2^32 (spec §4.14): a stream goes on past
    /// 4 GiB.
    pub const OFFSET_WRAP: Features = Features(1 << 2);
    /// Reserved for explicit post-proof authentication acceptance; not enabled yet.
    pub const AUTH_ACCEPTED: Features = Features(1 << 3);
    /// Reserved for ordered authoritative channel geometry; not enabled yet.
    pub const CHANNEL_GEOMETRY: Features = Features(1 << 4);
    /// What this build implements: what it offers as a client and may
    /// enable as a server.
    pub const SUPPORTED: Features =
        Features(Features::HEADER_AAD.0 | Features::STREAM_CREDIT.0 | Features::OFFSET_WRAP.0);

    /// The names the logs and `qshd self-check` use, bit by bit.
    const NAMES: [(Features, &'static str); 5] = [
        (Features::HEADER_AAD, "header-aad"),
        (Features::STREAM_CREDIT, "stream-credit"),
        (Features::OFFSET_WRAP, "offset-wrap"),
        (Features::AUTH_ACCEPTED, "auth-accepted"),
        (Features::CHANNEL_GEOMETRY, "channel-geometry"),
    ];

    /// The set these bits say, known or not.
    pub const fn from_bits(bits: u32) -> Features {
        Features(bits)
    }

    /// The bits as they go on the wire.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is in this set.
    pub const fn contains(self, other: Features) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Spec §5.2: on when the client offered it, this server allows it, and
    /// this build implements it. A function of msg1 and the configuration
    /// alone, so a retransmitted msg1 -- and its twin that went through
    /// probation on its own -- is answered the same.
    pub const fn negotiate(offered: Features, allowed: Features) -> Features {
        Features(offered.0 & allowed.0 & Features::SUPPORTED.0)
    }

    /// The names of the known bits in this set, in bit order.
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMES
            .iter()
            .filter(|(bit, _)| self.contains(*bit))
            .map(|(_, name)| *name)
            .collect()
    }

    /// The names, space-separated, or `none`.
    pub fn describe(self) -> String {
        let names = self.names();
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(" ")
        }
    }
}

impl BitOr for Features {
    type Output = Features;
    fn bitor(self, rhs: Features) -> Features {
        Features(self.0 | rhs.0)
    }
}

impl BitAnd for Features {
    type Output = Features;
    fn bitand(self, rhs: Features) -> Features {
        Features(self.0 & rhs.0)
    }
}

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Features({:#010x}: {})", self.0, self.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §5.1: the bit numbers are the wire's, fixed for good.
    #[test]
    fn the_bits_are_the_specs() {
        assert_eq!(Features::HEADER_AAD.bits(), 0x0000_0001);
        assert_eq!(Features::STREAM_CREDIT.bits(), 0x0000_0002);
        assert_eq!(Features::OFFSET_WRAP.bits(), 0x0000_0004);
        assert_eq!(Features::NONE.bits(), 0);
    }

    /// Spec §5.3/§5.5: the names the logs and `self-check` print, in bit
    /// order; a bit nobody has defined has no name.
    #[test]
    fn a_set_is_named_bit_by_bit_and_unknown_bits_have_no_name() {
        let all = Features::HEADER_AAD | Features::STREAM_CREDIT | Features::OFFSET_WRAP;
        assert_eq!(
            all.names(),
            vec!["header-aad", "stream-credit", "offset-wrap"]
        );
        assert_eq!(
            (Features::STREAM_CREDIT | Features::from_bits(1 << 9)).describe(),
            "stream-credit"
        );
        assert_eq!(Features::NONE.describe(), "none");
        assert!(Features::from_bits(1 << 31).names().is_empty());
    }

    /// Spec §5.2: on only when offered, allowed, and implemented -- a bit
    /// this build does not implement stays off whatever both sides say.
    #[test]
    fn negotiation_needs_the_offer_the_permission_and_the_implementation() {
        let unknown = Features::from_bits(1 << 20);
        let all = Features::HEADER_AAD | Features::STREAM_CREDIT | Features::OFFSET_WRAP | unknown;
        assert_eq!(Features::negotiate(all, all), Features::SUPPORTED);
        assert_eq!(
            Features::negotiate(Features::HEADER_AAD, Features::NONE),
            Features::NONE
        );
        assert_eq!(
            Features::negotiate(Features::NONE, Features::HEADER_AAD),
            Features::NONE
        );
        assert_eq!(
            Features::negotiate(unknown, all),
            Features::NONE,
            "nobody implements it"
        );
        assert_eq!(
            Features::SUPPORTED,
            Features::HEADER_AAD | Features::STREAM_CREDIT | Features::OFFSET_WRAP
        );
    }

    #[test]
    fn contains_is_a_subset_test() {
        let two = Features::HEADER_AAD | Features::OFFSET_WRAP;
        assert!(two.contains(Features::HEADER_AAD));
        assert!(two.contains(Features::NONE));
        assert!(!two.contains(Features::STREAM_CREDIT));
        assert!(!Features::HEADER_AAD.contains(two));
        assert_eq!(two & Features::OFFSET_WRAP, Features::OFFSET_WRAP);
    }
}

#[cfg(test)]
mod geometry_feature_tests {
    use super::*;

    #[test]
    fn geometry_bit_does_not_claim_auth_acceptance() {
        assert_eq!(Features::AUTH_ACCEPTED.bits(), 8);
        assert_eq!(Features::CHANNEL_GEOMETRY.bits(), 16);
        assert!(!Features::CHANNEL_GEOMETRY.contains(Features::AUTH_ACCEPTED));
        let reserved = Features::AUTH_ACCEPTED | Features::CHANNEL_GEOMETRY;
        assert_eq!(Features::negotiate(reserved, reserved), Features::NONE);
        assert_eq!(
            Features::negotiate(Features::from_bits(u32::MAX), Features::from_bits(u32::MAX)),
            Features::SUPPORTED
        );
        assert_eq!(Features::SUPPORTED & reserved, Features::NONE);
        assert_eq!(reserved.names(), vec!["auth-accepted", "channel-geometry"]);
    }
}
