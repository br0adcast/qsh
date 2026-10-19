//! The authentication layer's data plane: what a client sends to prove who it
//! is, and the two traits the platform plugs its crypto into.
//!
//! The transport deliberately knows nothing about SSH. It defines WHERE the
//! proof travels (a stream of its own), WHAT it commits to (the handshake
//! hash under a domain prefix) and HOW it is framed; parsing keys, talking to
//! an agent and checking `authorized_keys` all live in `crates/sshauth`. That
//! separation keeps key formats and signing backends out of the transport.

use std::fmt;
use std::time::Duration;

/// How long a client has to deliver its proof and the server to dispatch its
/// verification, including any wait for verification capacity. A blocking
/// verification already dispatched may finish after this deadline.
/// Short on purpose: an unauthenticated connection costs the server a routing
/// entry and a task, and a real client signs within one round trip.
///
/// It lives here, with the record it bounds, rather than with the server's
/// probation stage: this is equally the CLIENT's budget for producing a
/// proof, and the client driver (`crate::driver_std`) builds without the
/// `tokio-driver` feature that gates `crate::probation`.
pub const AUTH_DEADLINE: Duration = Duration::from_secs(5);

/// Allow a response already on the wire to arrive after the proof deadline.
pub const AUTH_DELIVERY_MARGIN: Duration = Duration::from_millis(500);

/// Client failure budget for explicit admission acceptance. Neither elapsed
/// time, transport keepalives nor application bytes establish authentication.
pub const AUTH_ACCEPTANCE_TIMEOUT: Duration = Duration::from_millis(
    AUTH_DEADLINE.as_millis() as u64 + AUTH_DELIVERY_MARGIN.as_millis() as u64,
);

/// How long a client waits for the handshake of a signature login to
/// complete AT ALL before giving up on the address. Nothing listening on the
/// port is the commonest shape of "unreachable" on UDP -- an ICMP
/// port-unreachable is deliberately swallowed and the driver keeps
/// retransmitting msg1 every 500 ms with no cap of its own -- so without a
/// deadline a client would wait forever. Twenty retransmissions: generous
/// for a bad link, short enough not to look wedged.
pub const HANDSHAKE_GIVE_UP_AFTER: Duration = Duration::from_secs(10);

/// The stream the AUTH record travels on. It is handled by the session layer
/// and NEVER reaches a backend: streams 0 (shell I/O), 1 (control) and 2
/// (tmux control channel) belong to the application, this one does not.
pub const AUTH_STREAM: u8 = 15;

/// Domain separation for the signature. An agent signs whatever it is asked
/// to, so without a protocol-specific prefix a signature taken here would be
/// reusable elsewhere -- and someone else's signature reusable here.
pub const AUTH_DOMAIN: &str = "qsh-auth-v1";

/// Version byte of the AUTH record framing.
pub const AUTH_RECORD_VERSION: u8 = 0x01;

/// Domain separation for a version 2 signature. Distinct from
/// [`AUTH_DOMAIN`] on purpose: a v2 record carries a login name, and a
/// verifier that accepted a v1 signature over a v2 record would be taking
/// that name on the client's word.
pub const AUTH_DOMAIN_V2: &str = "qsh-auth-v2";

/// Version byte of the version 2 AUTH record framing.
pub const AUTH_RECORD_VERSION_V2: u8 = 0x02;

/// Length of the server-issued nonce a version 2 record echoes back.
pub const AUTH_NONCE_LEN: usize = 16;

/// Longest login name a version 2 record may carry -- also the ceiling the
/// single-byte length field can express.
pub const AUTH_LOGIN_MAX: usize = 255;

/// [`AUTH_NONCE_LEN`] fresh bytes for a handshake's msg2, straight from the
/// operating system's own randomness (`getrandom`).
///
/// `OsRng`, never `thread_rng()`: a thread-local generator is seeded once
/// and then carried across every `fork` this process makes, so its state in
/// a child is a copy of its state in the parent. `rand` 0.8 registers a fork
/// handler that reseeds the child, and nothing in this workspace draws from
/// `thread_rng` before the system mode's split -- but both of those are
/// facts about other code, and the whole replay defence rests on these 16
/// bytes being unguessable and never repeated. `OsRng` asks the kernel every
/// time and has no state to inherit, so it needs neither fact to hold.
pub fn random_nonce() -> [u8; AUTH_NONCE_LEN] {
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    nonce
}

/// What version 2 adds: who to log in as, and the nonce the server issued
/// for THIS handshake.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthV2 {
    /// Login name: UTF-8, 1..=[`AUTH_LOGIN_MAX`] bytes, no `/` and no NUL.
    /// Checked by the codec, because it reaches a `getpwnam` on the other
    /// side: a `/` would turn a name into a path and a NUL would truncate
    /// it inside C.
    pub login: String,
    /// The nonce from msg2, echoed back under the signature so a proof made
    /// for one handshake cannot be presented for another.
    pub nonce: [u8; AUTH_NONCE_LEN],
}

/// The client's proof, as it travels on [`AUTH_STREAM`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthRecord {
    /// The client's SSH public key in the standard SSH wire encoding -- the
    /// same bytes that sit base64-encoded in `authorized_keys`.
    pub public_key: Vec<u8>,
    /// The SSH signature blob over [`auth_challenge`]. It names its own
    /// algorithm, so the record needs no separate algorithm field.
    pub signature: Vec<u8>,
    /// Present on a version 2 record, absent on a version 1 one. Which it
    /// is decides both the version byte on the wire and which challenge the
    /// signature covers.
    pub v2: Option<AuthV2>,
}

/// What went wrong while authenticating.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthError {
    /// The bytes seen so far are a consistent *prefix* of a well-formed
    /// record: nothing seen yet contradicts a valid record, there just
    /// are not enough bytes yet (a stream chunk boundary landed inside the
    /// record). The caller should buffer and feed more bytes, not treat the
    /// peer as malicious. A real AUTH record can be larger than a single
    /// transport segment, so this is the ordinary case, not a corner case.
    Incomplete,
    /// The record is malformed: wrong version, or trailing bytes left over
    /// after a complete record was parsed.
    BadRecord,
    /// The key parsed, but the signature does not verify over the challenge.
    BadSignature,
    /// The signature verified, but this key is not allowed in.
    KeyNotAuthorized,
    /// The proof never arrived in time.
    Timeout,
    /// Anything the platform side could not do (no agent, unreadable file,
    /// unsupported algorithm). Carries a message for the log, never for the
    /// wire.
    Backend(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Incomplete => f.write_str("authentication record is incomplete"),
            AuthError::BadRecord => f.write_str("malformed authentication record"),
            AuthError::BadSignature => f.write_str("signature does not verify"),
            AuthError::KeyNotAuthorized => f.write_str("key is not authorized"),
            AuthError::Timeout => f.write_str("no authentication record arrived in time"),
            AuthError::Backend(msg) => write!(f, "authentication backend: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The exact bytes a client signs and a server verifies: the domain prefix
/// followed by this session's handshake hash.
pub fn auth_challenge(handshake_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_DOMAIN.len() + 32);
    out.extend_from_slice(AUTH_DOMAIN.as_bytes());
    out.extend_from_slice(handshake_hash);
    out
}

/// The bytes a version 2 proof commits to. The login is in there because
/// otherwise anything standing between the client and `getpwnam` could swap
/// it for another account and still present a genuine signature; the nonce
/// is in there so a proof cannot be carried over into a second handshake.
///
/// The login goes last and carries no length of its own: everything before
/// it is fixed-width, so the split is unambiguous.
pub fn auth_challenge_v2(handshake_hash: &[u8; 32], v2: &AuthV2) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_DOMAIN_V2.len() + 32 + AUTH_NONCE_LEN + v2.login.len());
    out.extend_from_slice(AUTH_DOMAIN_V2.as_bytes());
    out.extend_from_slice(handshake_hash);
    out.extend_from_slice(&v2.nonce);
    out.extend_from_slice(v2.login.as_bytes());
    out
}

/// The challenge this record must verify against, whichever version it is.
/// Signer and verifier both go through here so neither can pick the wrong
/// domain for a record.
pub fn record_challenge(handshake_hash: &[u8; 32], record: &AuthRecord) -> Vec<u8> {
    match &record.v2 {
        None => auth_challenge(handshake_hash),
        Some(v2) => auth_challenge_v2(handshake_hash, v2),
    }
}

/// Frame a record: `version(1) | key_len(u16 BE) | key | sig_len(u16 BE) | sig`.
///
/// Both lengths are declared in a `u16`, so a field larger than that cannot be
/// framed at all. That is an ERROR rather than a `debug_assert`: the input
/// comes from the platform side (a key file, an agent), and a release build
/// silently truncating `len as u16` would emit a record that re-parses into
/// DIFFERENT content -- a shorter key followed by garbage -- instead of
/// failing. Unreachable with any real SSH key; refused anyway, because a codec
/// must never produce bytes that do not mean what it was handed.
pub fn encode_auth_record(record: &AuthRecord) -> Result<Vec<u8>, AuthError> {
    let field = |name: &str, len: usize| -> Result<u16, AuthError> {
        u16::try_from(len).map_err(|_| {
            AuthError::Backend(format!(
                "{name} of {len} bytes does not fit the record's u16 length field"
            ))
        })
    };
    let key_len = field("public key", record.public_key.len())?;
    let sig_len = field("signature", record.signature.len())?;
    let mut out = Vec::with_capacity(5 + record.public_key.len() + record.signature.len());
    match &record.v2 {
        None => out.push(AUTH_RECORD_VERSION),
        Some(v2) => {
            if !login_is_usable(&v2.login) {
                return Err(AuthError::Backend(format!(
                    "login name {:?} is not 1..={AUTH_LOGIN_MAX} bytes of UTF-8 free of '/' and NUL",
                    v2.login
                )));
            }
            out.push(AUTH_RECORD_VERSION_V2);
            out.extend_from_slice(&v2.nonce);
            out.push(v2.login.len() as u8);
            out.extend_from_slice(v2.login.as_bytes());
        }
    }
    out.extend_from_slice(&key_len.to_be_bytes());
    out.extend_from_slice(&record.public_key);
    out.extend_from_slice(&sig_len.to_be_bytes());
    out.extend_from_slice(&record.signature);
    Ok(out)
}

/// Whether a login name can be handed on as-is. Kept in one place so the
/// encoder and the parser cannot drift apart on what they accept.
fn login_is_usable(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= AUTH_LOGIN_MAX
        && !login.contains('/')
        && !login.contains('\0')
}

/// Parse a record. The input is untrusted network data, so every length is
/// checked against what is actually there.
///
/// Returns [`AuthError::Incomplete`] when the buffer ends mid-record (a
/// missing version byte, a missing length field, or a declared length that
/// overruns what has arrived so far) -- that is not an attack, just a chunk
/// boundary, and the caller should buffer and retry with more bytes.
/// Returns [`AuthError::BadRecord`] when the bytes present are inconsistent
/// with any well-formed record: a wrong version byte, or bytes left over
/// after a complete record was parsed.
pub fn parse_auth_record(bytes: &[u8]) -> Result<AuthRecord, AuthError> {
    let mut rest = bytes;
    let take = |rest: &mut &[u8], n: usize| -> Result<Vec<u8>, AuthError> {
        if rest.len() < n {
            return Err(AuthError::Incomplete);
        }
        let (head, tail) = rest.split_at(n);
        *rest = tail;
        Ok(head.to_vec())
    };
    let version = take(&mut rest, 1)?;
    let v2 = match version[0] {
        AUTH_RECORD_VERSION => None,
        AUTH_RECORD_VERSION_V2 => {
            let nonce: [u8; AUTH_NONCE_LEN] = take(&mut rest, AUTH_NONCE_LEN)?
                .try_into()
                .expect("exactly AUTH_NONCE_LEN bytes were taken");
            let login_len = take(&mut rest, 1)?[0] as usize;
            let login_bytes = take(&mut rest, login_len)?;
            // Malformed UTF-8 and an unusable name are both BadRecord, not
            // Incomplete: more bytes would not make either of them valid.
            let login = String::from_utf8(login_bytes).map_err(|_| AuthError::BadRecord)?;
            if !login_is_usable(&login) {
                return Err(AuthError::BadRecord);
            }
            Some(AuthV2 { login, nonce })
        }
        _ => return Err(AuthError::BadRecord),
    };
    let key_len = u16::from_be_bytes(
        take(&mut rest, 2)?
            .try_into()
            .expect("exactly two bytes were taken"),
    ) as usize;
    let public_key = take(&mut rest, key_len)?;
    let sig_len = u16::from_be_bytes(
        take(&mut rest, 2)?
            .try_into()
            .expect("exactly two bytes were taken"),
    ) as usize;
    let signature = take(&mut rest, sig_len)?;
    if !rest.is_empty() {
        return Err(AuthError::BadRecord);
    }
    Ok(AuthRecord {
        public_key,
        signature,
        v2,
    })
}

/// Who the server decided this connection is. The verifier builds it; the
/// session manager carries it to the backend, which runs the session as
/// this account.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Principal {
    /// The system account the session runs as.
    pub uid: u32,
    /// That account's login name. In the personal mode this is the name of
    /// the account the daemon itself runs as, whatever the client claimed:
    /// the daemon serves exactly one account, so there is nothing to select.
    pub name: String,
    /// Short human-readable identity for the log -- a key fingerprint or a
    /// comment. Never anything secret.
    pub identity: String,
    /// Which INCARNATION of this device's login the verifier admitted this
    /// connection under -- strictly increasing, and never reused once a
    /// login has ended and been admitted again under the same token.
    ///
    /// A device's token is stable across a roam and across a reconnect, so
    /// it cannot tell one life of a login from the next. Something has to,
    /// because a verifier that keeps state per login (the system mode's
    /// privileged helper, which holds a PAM session and a monitor process
    /// for each) also reports when one ENDS
    /// (`session_manager::LoginEndedReporter`), and those two messages race:
    /// they travel on separate sockets, are read by separate threads, and
    /// meet in one unbiased `select!`. Without a number to compare, a
    /// notice about a login that ended can be acted on after the same
    /// device has proved itself again, and tear down the session it just
    /// got.
    ///
    /// [`NO_INCARNATION`] from a verifier that keeps nothing per login --
    /// the personal mode's, and the allowlist path, which has no verifier at
    /// all. Such a server has no reporter either
    /// ([`session_manager::LoginEndedReports::none`]), so nothing ever
    /// compares the value.
    ///
    /// **A verifier that DOES keep state per login must never leave this at
    /// [`NO_INCARNATION`].** It is the natural thing to copy from a
    /// neighbouring literal, it compiles, and every test stays green --
    /// and it silently switches the staleness check off, so reports about
    /// logins that have already been replaced start being applied again and
    /// live sessions are torn down for them. Nothing anywhere will say so:
    /// the value is only ever compared, never validated, because there is no
    /// third state for "this verifier should have given me one and did not".
    pub incarnation: u64,
}

/// What [`Principal::incarnation`] carries when there is no such thing --
/// when the verifier keeps nothing per login, or when there is no verifier
/// at all.
///
/// It means ABSENCE, not "the zeroth life". Anything folding a fresh
/// admission's incarnation onto one already recorded has to tell those two
/// apart: a principal that says nothing must not overwrite a number that
/// says something (see `session_manager::incarnation_after`).
pub const NO_INCARNATION: u64 = 0;

/// Produces a client's proof, for example using ssh-agent or a key file.
pub trait AuthSigner: Send + Sync + 'static {
    /// Build the record proving this client's identity. `nonce` is the
    /// server's, from msg2 -- `None` from a server too old to send one, and
    /// then the record must be version 1, because there is nowhere to put a
    /// login.
    ///
    /// The login to claim is the signer's own: it is a property of the
    /// connection the caller configured, not of this handshake, and keeping
    /// it here is what stops it leaking into `StdClient::connect` and from
    /// there into every generated binding.
    ///
    /// Implementations MUST sign over [`record_challenge`] for the record
    /// they are building, never the raw hash and never the other version's
    /// challenge.
    fn sign(
        &self,
        handshake_hash: &[u8; 32],
        nonce: Option<&[u8; AUTH_NONCE_LEN]>,
    ) -> Result<AuthRecord, AuthError>;
}

/// Checks a client's proof. Implemented by the server side: on `qshd` by an
/// `authorized_keys` reader.
pub trait AuthVerifier: Send + Sync + 'static {
    /// Verify `record` against this session's `handshake_hash`. Implementations
    /// MUST verify the signature over `record_challenge(handshake_hash, record)`,
    /// never the raw hash -- a verifier that checked the bare hash would still
    /// interoperate with a signer that made the same mistake, silently
    /// discarding the domain separation this module exists to provide. On
    /// success returns the [`Principal`] this connection authenticated as.
    ///
    /// `login` is the router's own token for the device this handshake is
    /// for -- `session_manager::LoginId`, kept here as a bare `[u8; 16]`
    /// rather than that alias so this trait, compiled unconditionally, never
    /// depends on the `tokio-driver` feature `session_manager` needs. A
    /// verifier that cares which device this is (the system mode's helper,
    /// so it can create that device's login entry the moment it proves
    /// itself, before its first channel) reads it; one that does not (the
    /// personal mode's, which has only one device) ignores it.
    ///
    /// `rhost` is where this handshake came from, as this process saw it
    /// (`probation`'s `src`) -- for a verifier that records it or passes it
    /// on (the system mode's, whose helper keeps it for `PAM_RHOST` and for
    /// the log), and ignored by one that does not. It is a plain
    /// description of an address, not a promise about one: nothing decides
    /// anything by it, here or past here.
    fn verify(
        &self,
        handshake_hash: &[u8; 32],
        record: &AuthRecord,
        login: [u8; 16],
        rhost: &str,
    ) -> Result<Principal, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every nonce is a fresh one: a repeat would let a proof made for one
    /// handshake be presented for another, which is the entire reason msg2
    /// carries a nonce at all. Checked over several draws rather than one,
    /// the same way `Connection::accept`'s own nonce tests are.
    #[test]
    fn random_nonce_issues_a_fresh_value_every_time() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            assert!(seen.insert(random_nonce()), "a nonce repeated across draws");
        }
    }

    fn record() -> AuthRecord {
        AuthRecord {
            public_key: vec![1, 2, 3, 4],
            signature: vec![9; 70],
            v2: None,
        }
    }

    #[test]
    fn record_round_trips() {
        let bytes = encode_auth_record(&record()).expect("a record with ordinary fields encodes");
        assert_eq!(bytes[0], AUTH_RECORD_VERSION);
        assert_eq!(parse_auth_record(&bytes).unwrap(), record());
    }

    #[test]
    fn record_rejects_bad_version() {
        let mut bad = encode_auth_record(&record()).expect("encodes");
        bad[0] = 0x42;
        assert_eq!(parse_auth_record(&bad), Err(AuthError::BadRecord));
    }

    #[test]
    fn record_reports_incomplete_on_truncation() {
        let good = encode_auth_record(&record()).expect("encodes");
        for cut in [0, 1, 3, 5, good.len() - 1] {
            assert_eq!(
                parse_auth_record(&good[..cut]),
                Err(AuthError::Incomplete),
                "a truncated record must report Incomplete, not BadRecord (cut at {cut})"
            );
        }
    }

    #[test]
    fn record_rejects_trailing_bytes() {
        let mut with_extra = encode_auth_record(&record()).expect("encodes");
        with_extra.push(0xFF);
        assert_eq!(parse_auth_record(&with_extra), Err(AuthError::BadRecord));
    }

    #[test]
    fn record_round_trips_with_empty_fields() {
        let empty = AuthRecord {
            public_key: vec![],
            signature: vec![],
            v2: None,
        };
        let bytes = encode_auth_record(&empty).expect("empty fields encode");
        assert_eq!(parse_auth_record(&bytes), Ok(empty));
    }

    #[test]
    fn record_round_trips_at_u16_length_boundary() {
        let boundary = AuthRecord {
            public_key: vec![0xAB; u16::MAX as usize],
            signature: vec![0xCD; u16::MAX as usize],
            v2: None,
        };
        let bytes = encode_auth_record(&boundary).expect("the u16 boundary still encodes");
        assert_eq!(parse_auth_record(&bytes), Ok(boundary));
    }

    /// The deadline bounds the CLIENT's side of the exchange as much as the
    /// server's -- it is how long the client has to produce a proof -- and the
    /// client driver builds WITHOUT the `tokio-driver` feature, where
    /// `crate::probation` (its former home) does not exist at all. This module
    /// compiles in exactly that build, so referring to the constant here, and
    /// at the crate root where the platform side reaches for it, is the proof.
    #[test]
    fn the_auth_deadline_is_reachable_without_the_tokio_driver() {
        assert!(AUTH_DEADLINE > Duration::from_secs(0));
        assert_eq!(crate::AUTH_DEADLINE, AUTH_DEADLINE);
    }

    /// A field one byte past what the `u16` length can express is REFUSED.
    /// Truncating it (`len as u16`, which is what a `debug_assert` leaves a
    /// release build doing) would emit a record that parses back into
    /// different content instead of failing.
    #[test]
    fn an_over_long_field_is_refused_rather_than_truncated() {
        for record in [
            AuthRecord {
                public_key: vec![0xAB; u16::MAX as usize + 1],
                signature: vec![0xCD; 4],
                v2: None,
            },
            AuthRecord {
                public_key: vec![0xAB; 4],
                signature: vec![0xCD; u16::MAX as usize + 1],
                v2: None,
            },
        ] {
            match encode_auth_record(&record) {
                Err(AuthError::Backend(_)) => {}
                // Report the encoded LENGTH, not the bytes: a truncating
                // encoder would dump 64 KiB into the failure message.
                other => panic!(
                    "a field that does not fit the u16 length must be an error, got {:?}",
                    other.map(|bytes| bytes.len())
                ),
            }
        }
    }

    /// The domain prefix is what stops a signature made here from being
    /// replayed into another protocol that also asks an agent to sign.
    #[test]
    fn the_challenge_is_the_domain_then_the_hash() {
        let hash = [7u8; 32];
        let challenge = auth_challenge(&hash);
        assert_eq!(&challenge[..AUTH_DOMAIN.len()], AUTH_DOMAIN.as_bytes());
        assert_eq!(&challenge[AUTH_DOMAIN.len()..], &hash[..]);
        assert_ne!(auth_challenge(&[8u8; 32]), challenge);
    }

    fn v2_record() -> AuthRecord {
        AuthRecord {
            public_key: vec![1, 2, 3, 4],
            signature: vec![9; 70],
            v2: Some(AuthV2 {
                login: "alice".to_string(),
                nonce: [7u8; AUTH_NONCE_LEN],
            }),
        }
    }

    #[test]
    fn a_v2_record_round_trips() {
        let bytes = encode_auth_record(&v2_record()).expect("encodes");
        assert_eq!(bytes[0], AUTH_RECORD_VERSION_V2);
        assert_eq!(parse_auth_record(&bytes).unwrap(), v2_record());
    }

    #[test]
    fn a_v2_record_reports_incomplete_on_truncation() {
        let good = encode_auth_record(&v2_record()).expect("encodes");
        for cut in [0, 1, 8, 17, 18, good.len() - 1] {
            assert_eq!(
                parse_auth_record(&good[..cut]),
                Err(AuthError::Incomplete),
                "a truncated v2 record must report Incomplete (cut at {cut})"
            );
        }
    }

    /// A login reaching `getpwnam` unchecked is how a name becomes a path.
    #[test]
    fn a_v2_record_refuses_an_unusable_login_on_parse() {
        for bad in ["", "ali/ce", "ali\0ce"] {
            let mut bytes = vec![AUTH_RECORD_VERSION_V2];
            bytes.extend_from_slice(&[7u8; AUTH_NONCE_LEN]);
            bytes.push(bad.len() as u8);
            bytes.extend_from_slice(bad.as_bytes());
            bytes.extend_from_slice(&4u16.to_be_bytes());
            bytes.extend_from_slice(&[1, 2, 3, 4]);
            bytes.extend_from_slice(&2u16.to_be_bytes());
            bytes.extend_from_slice(&[9, 9]);
            assert_eq!(
                parse_auth_record(&bytes),
                Err(AuthError::BadRecord),
                "login {bad:?} must be refused"
            );
        }
    }

    /// The two domains must not share a prefix that would let one signature
    /// stand in for the other.
    #[test]
    fn the_v2_challenge_differs_from_the_v1_one() {
        let hash = [3u8; 32];
        let v2 = AuthV2 {
            login: "alice".to_string(),
            nonce: [7u8; AUTH_NONCE_LEN],
        };
        let v1 = auth_challenge(&hash);
        let two = auth_challenge_v2(&hash, &v2);
        assert_ne!(v1, two);
        assert!(
            !two.starts_with(&v1),
            "a v1 challenge must not prefix a v2 one"
        );
    }

    /// The login is under the signature: change it and the signed bytes change.
    #[test]
    fn the_v2_challenge_covers_the_login_and_the_nonce() {
        let hash = [3u8; 32];
        let base = AuthV2 {
            login: "alice".to_string(),
            nonce: [7u8; AUTH_NONCE_LEN],
        };
        let other_login = AuthV2 {
            login: "root".to_string(),
            ..base.clone()
        };
        let other_nonce = AuthV2 {
            nonce: [8u8; AUTH_NONCE_LEN],
            ..base.clone()
        };
        assert_ne!(
            auth_challenge_v2(&hash, &base),
            auth_challenge_v2(&hash, &other_login)
        );
        assert_ne!(
            auth_challenge_v2(&hash, &base),
            auth_challenge_v2(&hash, &other_nonce)
        );
    }

    #[test]
    fn record_challenge_picks_the_version() {
        let hash = [3u8; 32];
        let v1 = AuthRecord {
            public_key: vec![1],
            signature: vec![2],
            v2: None,
        };
        assert_eq!(record_challenge(&hash, &v1), auth_challenge(&hash));
        let two = v2_record();
        let fields = two.v2.clone().expect("v2 fields");
        assert_eq!(
            record_challenge(&hash, &two),
            auth_challenge_v2(&hash, &fields)
        );
    }
}
