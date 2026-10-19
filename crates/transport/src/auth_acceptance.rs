//! The server's committed admission result, independent of client signatures.

use crate::Features;

/// Exactly one server-direction record is allowed on the authentication stream.
pub const AUTH_ACCEPTANCE_LEN: usize = 12;

/// What the admitted transport actually acquired after the admission commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDisposition {
    Fresh,
    Resumed,
}

/// Authenticated admission of one exact transport, not permission to open a shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthAcceptance {
    pub session_id: u64,
    pub disposition: SessionDisposition,
}

/// A fixed, bounded reason for refusing server-direction authentication bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthAcceptanceError {
    Malformed,
    WrongSession,
    Unnegotiated,
    Excess,
}

/// Encode the committed result without allocating or sharing signature framing.
pub fn encode_auth_acceptance(record: AuthAcceptance) -> [u8; AUTH_ACCEPTANCE_LEN] {
    let mut bytes = [0; AUTH_ACCEPTANCE_LEN];
    bytes[0] = 1;
    bytes[1] = 1;
    bytes[2] = match record.disposition {
        SessionDisposition::Fresh => 0,
        SessionDisposition::Resumed => 1,
    };
    bytes[4..].copy_from_slice(&record.session_id.to_be_bytes());
    bytes
}

/// Decode exactly one complete record. The owner separately validates session identity.
pub fn decode_auth_acceptance(bytes: &[u8]) -> Result<AuthAcceptance, AuthAcceptanceError> {
    if bytes.len() != AUTH_ACCEPTANCE_LEN || bytes[0] != 1 || bytes[1] != 1 || bytes[3] != 0 {
        return Err(AuthAcceptanceError::Malformed);
    }
    let disposition = match bytes[2] {
        0 => SessionDisposition::Fresh,
        1 => SessionDisposition::Resumed,
        _ => return Err(AuthAcceptanceError::Malformed),
    };
    Ok(AuthAcceptance {
        session_id: u64::from_be_bytes(bytes[4..].try_into().expect("fixed record length")),
        disposition,
    })
}

/// Per-connection bounded state. A delivered result is never delivered twice.
pub(crate) struct AuthAcceptanceParser {
    bytes: [u8; AUTH_ACCEPTANCE_LEN],
    len: usize,
    session_id: u64,
    negotiated: bool,
    accepted: bool,
    failed: Option<AuthAcceptanceError>,
}

impl AuthAcceptanceParser {
    pub(crate) fn new(session_id: u64, features: Features) -> Self {
        Self {
            bytes: [0; AUTH_ACCEPTANCE_LEN],
            len: 0,
            session_id,
            negotiated: features.contains(Features::AUTH_ACCEPTED),
            accepted: false,
            failed: None,
        }
    }

    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<AuthAcceptance>, AuthAcceptanceError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        if !self.negotiated {
            return self.fail(AuthAcceptanceError::Unnegotiated);
        }
        if self.accepted || bytes.len() > AUTH_ACCEPTANCE_LEN - self.len {
            return self.fail(AuthAcceptanceError::Excess);
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        if self.len < AUTH_ACCEPTANCE_LEN {
            return Ok(None);
        }
        let record = match decode_auth_acceptance(&self.bytes) {
            Ok(record) => record,
            Err(error) => return self.fail(error),
        };
        if record.session_id != self.session_id {
            return self.fail(AuthAcceptanceError::WrongSession);
        }
        self.accepted = true;
        Ok(Some(record))
    }

    fn fail<T>(&mut self, error: AuthAcceptanceError) -> Result<T, AuthAcceptanceError> {
        self.failed = Some(error);
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: u64 = 0x0102_0304_0506_0708;

    fn record(disposition: SessionDisposition) -> AuthAcceptance {
        AuthAcceptance {
            session_id: SESSION,
            disposition,
        }
    }

    fn wire(disposition: u8) -> [u8; 12] {
        [1, 1, disposition, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    }

    fn parser() -> AuthAcceptanceParser {
        AuthAcceptanceParser::new(SESSION, Features::AUTH_ACCEPTED)
    }

    #[test]
    fn auth17_exact_wire_is_twelve_bytes_with_committed_disposition() {
        for (kind, disposition) in [
            (0, SessionDisposition::Fresh),
            (1, SessionDisposition::Resumed),
        ] {
            assert_eq!(encode_auth_acceptance(record(disposition)), wire(kind));
            assert_eq!(decode_auth_acceptance(&wire(kind)), Ok(record(disposition)));
        }
    }

    #[test]
    fn auth17_rejects_every_unknown_fixed_field_and_wrong_record_length() {
        for field in 0..4 {
            for invalid in 0..=u8::MAX {
                if (field < 2 && invalid == 1)
                    || (field == 2 && invalid <= 1)
                    || (field == 3 && invalid == 0)
                {
                    continue;
                }
                let mut bytes = wire(0);
                bytes[field] = invalid;
                assert_eq!(
                    decode_auth_acceptance(&bytes),
                    Err(AuthAcceptanceError::Malformed)
                );
            }
        }
        for len in 0..12 {
            assert_eq!(
                decode_auth_acceptance(&wire(0)[..len]),
                Err(AuthAcceptanceError::Malformed)
            );
        }
        assert_eq!(
            decode_auth_acceptance(&[wire(0).as_slice(), &[0]].concat()),
            Err(AuthAcceptanceError::Malformed)
        );
    }

    #[test]
    fn auth17_every_chunk_split_delivers_exactly_once() {
        for split in 0..=12 {
            let mut parser = parser();
            let mut accepted = Vec::new();
            for chunk in [&wire(1)[..split], &wire(1)[split..]] {
                accepted.extend(parser.feed(chunk).unwrap());
                assert!(parser.len <= AUTH_ACCEPTANCE_LEN);
            }
            assert_eq!(accepted, vec![record(SessionDisposition::Resumed)]);
            assert_eq!(parser.feed(&[]), Ok(None));
        }
    }

    #[test]
    fn auth17_one_byte_chunks_hold_no_unbounded_partial_record() {
        let mut parser = parser();
        for (at, byte) in wire(0).iter().enumerate() {
            let accepted = parser.feed(std::slice::from_ref(byte)).unwrap();
            assert_eq!(
                accepted,
                (at == 11).then_some(record(SessionDisposition::Fresh))
            );
            assert_eq!(parser.len, at + 1);
        }
    }

    #[test]
    fn auth17_unnegotiated_bytes_and_wrong_session_are_terminal() {
        let mut missing = AuthAcceptanceParser::new(SESSION, Features::CHANNEL_GEOMETRY);
        assert_eq!(
            missing.feed(&wire(0)),
            Err(AuthAcceptanceError::Unnegotiated)
        );
        assert_eq!(missing.len, 0);
        let mut stale = AuthAcceptanceParser::new(SESSION + 1, Features::AUTH_ACCEPTED);
        assert_eq!(stale.feed(&wire(0)), Err(AuthAcceptanceError::WrongSession));
        assert_eq!(stale.feed(&wire(1)), Err(AuthAcceptanceError::WrongSession));
    }

    #[test]
    fn auth17_excess_in_first_complete_chunk_never_delivers_acceptance() {
        for prefix in 0..12 {
            let mut parser = parser();
            assert_eq!(parser.feed(&wire(0)[..prefix]), Ok(None));
            let mut rest = wire(0)[prefix..].to_vec();
            rest.push(0);
            assert_eq!(parser.feed(&rest), Err(AuthAcceptanceError::Excess));
            assert_eq!(parser.len, prefix, "check the bound before copying");
            assert_eq!(parser.feed(&[]), Err(AuthAcceptanceError::Excess));
        }
        let mut parser = parser();
        assert_eq!(
            parser.feed(&[wire(0), wire(1)].concat()),
            Err(AuthAcceptanceError::Excess)
        );
        assert_eq!(parser.len, 0);
    }

    #[test]
    fn auth17_later_extra_bytes_fail_without_retracting_or_repeating_callback() {
        let mut parser = parser();
        assert_eq!(
            parser.feed(&wire(0)),
            Ok(Some(record(SessionDisposition::Fresh)))
        );
        assert_eq!(parser.feed(&[0]), Err(AuthAcceptanceError::Excess));
        assert_eq!(parser.feed(&wire(1)), Err(AuthAcceptanceError::Excess));
    }

    #[test]
    fn auth17_malformed_full_record_cannot_be_repaired_by_later_input() {
        let mut parser = parser();
        let mut bad = wire(0);
        bad[3] = 1;
        assert_eq!(parser.feed(&bad), Err(AuthAcceptanceError::Malformed));
        assert_eq!(parser.feed(&wire(0)), Err(AuthAcceptanceError::Malformed));
    }
}
