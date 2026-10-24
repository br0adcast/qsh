//! Noise IK handshake and transport encryption on top of the snow library.
//! snow runs the Noise IK handshake and yields its hash and its split; the
//! transport keys seal and open datagrams with `chacha20poly1305` directly
//! (spec §4.9), because snow's transport state takes no associated data.
//!
//! The module does no I/O (sans-IO): the caller decides how to deliver
//! handshake bytes and encrypted messages over the network.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use snow::{Builder, HandshakeState};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::wire::TRANSPORT_HEADER_LEN;

/// Noise parameters, fixed for the whole project.
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// X25519 static key length in bytes.
const KEY_LEN: usize = 32;

/// Buffer headroom over the payload length for IK handshake messages:
/// ephemeral public key (32) + AEAD-encrypted static key with tag (32 + 16) +
/// AEAD tag of the payload (16) = 96 bytes with margin (the second handshake
/// message actually uses less).
const HANDSHAKE_OVERHEAD: usize = 96;

/// Parse the fixed Noise parameter string.
fn noise_params() -> snow::params::NoiseParams {
    NOISE_PARAMS
        .parse()
        .expect("the Noise parameter string is fixed in code and always valid")
}

/// Copy a slice into a fixed 32-byte X25519 key array.
fn to_key(bytes: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(bytes);
    out
}

/// An X25519 static key pair (private and public).
/// The owned private array is erased on drop; caller copies and snow's
/// internal buffers are outside this guarantee.
pub struct Keypair {
    pub private: [u8; KEY_LEN],
    pub public: [u8; KEY_LEN],
}

impl Zeroize for Keypair {
    fn zeroize(&mut self) {
        self.private.zeroize();
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Keypair {}

/// Generate a new random X25519 static key pair.
pub fn generate_keypair() -> Keypair {
    let mut kp = Builder::new(noise_params())
        .generate_keypair()
        .expect("Noise key generation cannot fail with fixed parameters");
    let keypair = Keypair {
        private: to_key(&kp.private),
        public: to_key(&kp.public),
    };
    kp.private.zeroize();
    keypair
}

/// Noise transport-layer error. `Noise` wraps `snow::Error` so the snow
/// dependency is not leaked verbatim into the public interface.
#[derive(Debug)]
pub enum TransportError {
    /// A handshake message did not read: malformed, forged, or for other keys.
    Noise(snow::Error),
    /// A transport message failed its tag: forged, corrupted, or sealed under
    /// other keys or another header.
    Decrypt,
    /// Sealing failed (a message too long for the AEAD).
    Encrypt,
    /// The counter is 2^64 - 1, which Noise reserves: refused both ways.
    NonceExhausted,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Noise(e) => write!(f, "Noise handshake error: {e}"),
            TransportError::Decrypt => f.write_str("a transport message failed its tag"),
            TransportError::Encrypt => f.write_str("a transport message could not be sealed"),
            TransportError::NonceExhausted => f.write_str("the nonce counter is exhausted"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Noise(e) => Some(e),
            _ => None,
        }
    }
}

impl From<snow::Error> for TransportError {
    fn from(err: snow::Error) -> Self {
        TransportError::Noise(err)
    }
}

/// A Noise IK handshake. The initiator (client) knows the responder's public
/// static key in advance; the responder (server) learns the initiator's
/// public static key from the handshake itself.
pub struct Handshake {
    // `Option` so `into_transport` can take the `HandshakeState` by value
    // while only holding `&mut self`/`self`.
    state: Option<HandshakeState>,
}

impl Handshake {
    /// Start a handshake as the initiator (client).
    pub fn new_initiator(local_priv: &[u8; KEY_LEN], remote_pub: &[u8; KEY_LEN]) -> Self {
        let state = Builder::new(noise_params())
            .local_private_key(local_priv)
            .remote_public_key(remote_pub)
            .build_initiator()
            .expect("building an IK initiator with valid keys cannot fail");
        Self { state: Some(state) }
    }

    /// Start a handshake as the responder (server). The initiator's static
    /// key is not known to the responder in advance -- it arrives in the
    /// first handshake message.
    pub fn new_responder(local_priv: &[u8; KEY_LEN]) -> Self {
        let state = Builder::new(noise_params())
            .local_private_key(local_priv)
            .build_responder()
            .expect("building an IK responder with a valid key cannot fail");
        Self { state: Some(state) }
    }

    /// Produce the next handshake message with an optional extra payload
    /// (usually empty, except for the final message).
    pub fn write_msg(&mut self, payload: &[u8]) -> Vec<u8> {
        let state = self.active_state_mut();
        let mut buf = vec![0u8; payload.len() + HANDSHAKE_OVERHEAD];
        let n = state
            .write_message(payload, &mut buf)
            .expect("the handshake buffer has margin, overflow is excluded");
        buf.truncate(n);
        buf
    }

    /// Process an incoming handshake message and return its embedded
    /// payload. Returns an error (not a panic) on corrupted or malicious
    /// data -- the input comes from the network and is untrusted.
    pub fn read_msg(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        let state = self.active_state_mut();
        let mut buf = vec![0u8; bytes.len()];
        let n = state.read_message(bytes, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Whether the handshake is finished (both sides have exchanged all
    /// messages).
    pub fn is_finished(&self) -> bool {
        self.state
            .as_ref()
            .map(HandshakeState::is_handshake_finished)
            .unwrap_or(false)
    }

    /// The remote side's public static key, if already known. Available to
    /// the responder after reading the first message -- used by the caller,
    /// e.g. for a client allowlist.
    pub fn remote_static(&self) -> Option<[u8; KEY_LEN]> {
        let bytes = self.state.as_ref()?.get_remote_static()?;
        Some(to_key(bytes))
    }

    /// The Noise handshake hash `h` of this session: both sides derive the
    /// same value, and it commits to both static keys and both ephemerals, so
    /// it is unique per session. The SSH-signature auth layer signs it, which
    /// is what binds a signature to THIS connection and makes it useless
    /// anywhere else.
    ///
    /// Must be read BEFORE `into_transport` takes the state by value.
    pub fn handshake_hash(&self) -> [u8; 32] {
        let state = self
            .state
            .as_ref()
            .expect("the handshake hash is read before into_transport");
        let mut out = [0u8; 32];
        // BLAKE2s: the hash is exactly 32 bytes for our fixed parameter set.
        out.copy_from_slice(&state.get_handshake_hash()[..32]);
        out
    }

    /// Finish the handshake and obtain the transport keys: Noise's split,
    /// the initiator sealing with the first key and opening with the second,
    /// the responder the other way round (as snow's transport state does).
    /// `header_aad`: whether the connection negotiated `header-aad` -- the
    /// 18-byte datagram header is then the associated data.
    pub fn into_transport(mut self, header_aad: bool) -> TransportKeys {
        let mut state = self
            .state
            .take()
            .expect("into_transport is called exactly once after the handshake finishes");
        assert!(
            state.is_handshake_finished(),
            "the transport keys are taken after the handshake finishes"
        );
        let (k1, k2) = state.dangerously_get_raw_split();
        let k1 = Zeroizing::new(k1);
        let k2 = Zeroizing::new(k2);
        // These owned split copies drop once the ciphers hold the keys.
        TransportKeys::from_split(state.is_initiator(), &k1, &k2, header_aad)
    }

    fn active_state_mut(&mut self) -> &mut HandshakeState {
        self.state
            .as_mut()
            .expect("the handshake was already moved to transport mode via into_transport")
    }
}

/// The transport keys of one side of a Noise session: one to seal what it
/// sends, one to open what it receives -- so the same counter is safe in
/// both directions at once. The ciphers wipe their keys when dropped.
pub struct TransportKeys {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    header_aad: bool,
}

impl TransportKeys {
    /// Build the keys from Noise's raw split `(k1, k2)`: the initiator seals
    /// with `k1`, the responder with `k2`. Borrows the split: its owner wipes
    /// it.
    fn from_split(
        initiator: bool,
        k1: &[u8; KEY_LEN],
        k2: &[u8; KEY_LEN],
        header_aad: bool,
    ) -> Self {
        let (send, recv) = if initiator { (k1, k2) } else { (k2, k1) };
        TransportKeys {
            send: ChaCha20Poly1305::new(Key::from_slice(send)),
            recv: ChaCha20Poly1305::new(Key::from_slice(recv)),
            header_aad,
        }
    }

    /// Whether `header` is the associated data (`header-aad` negotiated).
    pub fn header_aad(&self) -> bool {
        self.header_aad
    }

    /// Seal `plaintext` under `counter`, the AEAD nonce -- the caller keeps
    /// it unique within one direction (replay and reordering protection for
    /// datagrams is the protocol layer's job). `header` is the datagram's
    /// 18-byte header: the associated data when `header_aad`, unused
    /// otherwise. Fixed-size, so no other bytes can stand in for it.
    pub fn encrypt(
        &self,
        counter: u64,
        header: &[u8; TRANSPORT_HEADER_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let nonce = nonce_for(counter)?;
        self.send
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: self.aad(header),
                },
            )
            .map_err(|_| TransportError::Encrypt)
    }

    /// Open a message sealed under `counter` and `header`. A forged or
    /// corrupted one is an error, not a panic -- the input comes from the
    /// network and is untrusted.
    pub fn decrypt(
        &self,
        counter: u64,
        header: &[u8; TRANSPORT_HEADER_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let nonce = nonce_for(counter)?;
        self.recv
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: self.aad(header),
                },
            )
            .map_err(|_| TransportError::Decrypt)
    }

    fn aad<'a>(&self, header: &'a [u8; TRANSPORT_HEADER_LEN]) -> &'a [u8] {
        if self.header_aad {
            header
        } else {
            &[]
        }
    }
}

/// Noise's ChaCha20-Poly1305 nonce: four zero bytes, then the counter
/// little-endian. 2^64 - 1 is reserved (Noise §5.1) and refused.
fn nonce_for(counter: u64) -> Result<Nonce, TransportError> {
    if counter == u64::MAX {
        return Err(TransportError::NonceExhausted);
    }
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Ok(*Nonce::from_slice(&nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::{Blake2s256, Digest};
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    use snow::StatelessTransportState;

    /// Buffer headroom for transport messages -- one AEAD authentication tag.
    const TRANSPORT_TAG_LEN: usize = 16;

    /// Fixed keys for the reference vectors (spec §4.9): the static and the
    /// ephemeral private key of each side.
    const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
    const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
    const INITIATOR_EPHEMERAL: [u8; 32] = [0x33; 32];
    const RESPONDER_EPHEMERAL: [u8; 32] = [0x44; 32];
    const COUNTERS: [u64; 5] = [1, 2, 255, 1 << 32, 1 << 63];
    const LENGTHS: [usize; 4] = [0, 1, 1024, 1166];

    fn public_of(private: &[u8; 32]) -> [u8; 32] {
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .expect("snow's default resolver has X25519");
        dh.set(private);
        to_key(dh.pubkey())
    }

    /// Both sides of one handshake with fixed keys, finished, as snow left
    /// them. Deterministic: every call yields the same keys and hash.
    fn finished_fixed_handshake() -> (HandshakeState, HandshakeState) {
        let responder_pub = public_of(&RESPONDER_STATIC);
        let mut ini = Builder::new(noise_params())
            .local_private_key(&INITIATOR_STATIC)
            .remote_public_key(&responder_pub)
            .fixed_ephemeral_key_for_testing_only(&INITIATOR_EPHEMERAL)
            .build_initiator()
            .expect("initiator");
        let mut res = Builder::new(noise_params())
            .local_private_key(&RESPONDER_STATIC)
            .fixed_ephemeral_key_for_testing_only(&RESPONDER_EPHEMERAL)
            .build_responder()
            .expect("responder");
        let (mut msg, mut payload) = ([0u8; 256], [0u8; 256]);
        let n = ini.write_message(&[], &mut msg).expect("msg1");
        res.read_message(&msg[..n], &mut payload)
            .expect("msg1 reads");
        let n = res.write_message(&[], &mut msg).expect("msg2");
        ini.read_message(&msg[..n], &mut payload)
            .expect("msg2 reads");
        (ini, res)
    }

    /// This module's keys and snow's own transport state, from the same
    /// finished handshake.
    fn ours_and_snows(
        mut st: HandshakeState,
        header_aad: bool,
    ) -> (TransportKeys, StatelessTransportState) {
        let (k1, k2) = st.dangerously_get_raw_split();
        let ours = TransportKeys::from_split(st.is_initiator(), &k1, &k2, header_aad);
        let snow = st
            .into_stateless_transport_mode()
            .expect("the handshake is finished");
        (ours, snow)
    }

    fn plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + len) as u8).collect()
    }

    fn header(counter: u64) -> [u8; 18] {
        crate::wire::transport_header(0x0102_0304_0506_0708, counter)
    }

    // The audited golden vectors include a protocol-1 AAD byte. Keep that
    // exact fixture while normal connection/header tests exercise protocol 2.
    fn pinned_header(counter: u64) -> [u8; 18] {
        let mut header = header(counter);
        header[0] = 1;
        header
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Short ciphertexts in full; long ones as their BLAKE2s-256.
    fn fingerprint(ct: &[u8]) -> String {
        if ct.len() <= 64 {
            hex(ct)
        } else {
            format!("blake2s:{}", hex(&Blake2s256::digest(ct)))
        }
    }

    /// Spec §4.9 (a): with the header left out, a ciphertext is exactly
    /// what `StatelessTransportState::write_message` made of the same
    /// handshake -- every counter, every length, both directions -- and
    /// each side reads the other's.
    #[test]
    fn the_old_mode_seals_exactly_as_snow_did() {
        let (ini, res) = finished_fixed_handshake();
        let (ours_i, snow_i) = ours_and_snows(ini, false);
        let (ours_r, snow_r) = ours_and_snows(res, false);
        for (sender, (ours_tx, snow_tx, ours_rx, snow_rx)) in [
            ("initiator", (&ours_i, &snow_i, &ours_r, &snow_r)),
            ("responder", (&ours_r, &snow_r, &ours_i, &snow_i)),
        ] {
            for c in COUNTERS {
                for len in LENGTHS {
                    let pt = plaintext(len);
                    let ct = ours_tx.encrypt(c, &header(c), &pt).expect("seals");
                    let mut reference = vec![0u8; len + TRANSPORT_TAG_LEN];
                    let n = snow_tx
                        .write_message(c, &pt, &mut reference)
                        .expect("snow seals");
                    assert_eq!(ct, reference[..n], "{sender}, counter {c}, {len} bytes");
                    assert_eq!(
                        ours_rx
                            .decrypt(c, &header(c), &reference[..n])
                            .expect("opens snow's"),
                        pt
                    );
                    let mut back = vec![0u8; n];
                    let m = snow_rx
                        .read_message(c, &ct, &mut back)
                        .expect("snow opens ours");
                    assert_eq!(back[..m], pt[..], "{sender}, counter {c}, {len} bytes");
                }
            }
        }
    }

    /// What `print_the_reference_vectors` printed once: the old mode's bytes
    /// as snow made them, and two of the new mode's. Pinned so an update of
    /// snow or chacha20poly1305 cannot move the wire unnoticed (spec §4.9
    /// (b)). `(sender, counter, length, fingerprint)`.
    #[rustfmt::skip]
    const REFERENCE_VECTORS: &[(&str, u64, usize, &str)] = &[
        ("initiator", 1, 0, "1d73e4afe1ea572096e08015d0ba71d7"),
        ("initiator", 1, 1, "2e0ebe5c5971a7f368a23a1f8b34f8224e"),
        ("initiator", 1, 1024, "blake2s:0d2cdac0070c7b392617acb82cc036f4e2cb6c3a67cbfa124515304377a7348c"),
        ("initiator", 1, 1166, "blake2s:fd366431631de2ef5c6d6630720644dc86c24f8160e8d4b235545aaac6952510"),
        ("initiator", 2, 0, "8e081ea14bae801b9e58888527be6d86"),
        ("initiator", 2, 1, "ea8fe7293cb2801bcb4e863c5712a3e776"),
        ("initiator", 2, 1024, "blake2s:1126d7ccaf0cebd9831e0c16f311b00b34a1e18f8d7a90f9e577457ed940a889"),
        ("initiator", 2, 1166, "blake2s:afb2fa958329950b46588c3c752919d2e4ec092b69890aafb8c04a5102088a3f"),
        ("initiator", 255, 0, "e888fcaaa896ca5a2f1915592129335a"),
        ("initiator", 255, 1, "7f7ee4c08185a04d30d9c434a6fba02785"),
        ("initiator", 255, 1024, "blake2s:b2977d2b729d00e59a770f5a7b380ebf60b65f9ecfc844e22a8863587d536faf"),
        ("initiator", 255, 1166, "blake2s:8722b2479e9ef0d8b4a26e73431fc24d6ee596dad0e031406e8873a7c2430038"),
        ("initiator", 4294967296, 0, "b7c9b8e3650771980343adfbfab59216"),
        ("initiator", 4294967296, 1, "f0e0e683e57ba870f807d87f1d171fbc5c"),
        ("initiator", 4294967296, 1024, "blake2s:84e81873ebf644b78cd3b55858e9714b0ab677b90fa145d178d7c6ffedd3c53a"),
        ("initiator", 4294967296, 1166, "blake2s:18e71a7fb5bbe1ba15834a89894c17a347acce93636babb30501577536081e76"),
        ("initiator", 9223372036854775808, 0, "7106b9525d2c079b0a4d83c0265bf004"),
        ("initiator", 9223372036854775808, 1, "60b8267ab3ddab87c29e8eea8f1f376624"),
        ("initiator", 9223372036854775808, 1024, "blake2s:4e9033547f0d08d08266e204fafa7f8d624dc74a71878121a5734234e90ec978"),
        ("initiator", 9223372036854775808, 1166, "blake2s:a1a742b6e543650d66dad1fd5c1293a83d77c8a383b92a86cbaf2c31043adc95"),
        ("responder", 1, 0, "fd30604dc677f0fa0f7d314d4e4c6e84"),
        ("responder", 1, 1, "cdf50e5980e3c173e24cc0fe5509e90f81"),
        ("responder", 1, 1024, "blake2s:3aad6d02ca7c4d846d7f5a833ba92a307b1614239ec9cd50bccf8a01c576b799"),
        ("responder", 1, 1166, "blake2s:2c2b01c8e2417a8e8bf785a3593746be6d120667d9cde016ebf323b2feb4ff88"),
        ("responder", 2, 0, "a08332f77eae13fbc27122a17aa55c7f"),
        ("responder", 2, 1, "526b9ed7a3838bed5006893027f777ebbc"),
        ("responder", 2, 1024, "blake2s:4047e3a86d9c23d29654fbbbc003b20d64eb81ae27c499afa19089652dd0c8b6"),
        ("responder", 2, 1166, "blake2s:4b7ddcb3f0e50e9c4e71c186c241254b05a78f57cd8ed7abab5abd310fb6e84a"),
        ("responder", 255, 0, "5667f3cc08f496b43a99f64301afe0f5"),
        ("responder", 255, 1, "4383cb6ec4872ab6bbdf07895472784593"),
        ("responder", 255, 1024, "blake2s:cbbbdd4567f59950a9fa1e1ee9b6262e01ddd5fbb69ddc7f9f2e743e9acfaf1e"),
        ("responder", 255, 1166, "blake2s:8d2cb2bc416ff6148226588a4f531b45b3d47596b01a21f5acdf5ed87a1591d7"),
        ("responder", 4294967296, 0, "90e97fa0b478dd6687da12526b1d0dda"),
        ("responder", 4294967296, 1, "e3ad210524571735abce53aea61acf0372"),
        ("responder", 4294967296, 1024, "blake2s:e62386b1b34f7e6a0e8744b1d5e1bd9f8fc18029108d11ecbbc6f61f3a427496"),
        ("responder", 4294967296, 1166, "blake2s:d3e809d48aadbca6f5a0fd44e9c1b68990582ec9107fe33a8d0d8ef120ba8c52"),
        ("responder", 9223372036854775808, 0, "bad5efd86abb02bd44b9f5a1b795e54a"),
        ("responder", 9223372036854775808, 1, "d9bb9955a132e28bfba01ec4c341aa0595"),
        ("responder", 9223372036854775808, 1024, "blake2s:481993dbb972d0272e4d1400123307feeeb8d67cde578ea0f9049dd8be58cb5b"),
        ("responder", 9223372036854775808, 1166, "blake2s:1bdab5c59eca97c54864fa5881863d103ac30336d24aaa1d1f98f51dacd477aa"),
        ("initiator+header", 1, 0, "19e070fe122ce8182782c0e89b1bf65e"),
        ("initiator+header", 1, 1, "2e88e063fa476be3aff7d8e2cf1443b9ff"),
    ];

    /// The split keys and the handshake hash of `finished_fixed_handshake`,
    /// printed with the vectors.
    const REFERENCE_SPLIT: (&str, &str, &str) = (
        "eca6bee256efc1368a5af89be3a82cc3e7954223faf3d6b4e67ed66c671a814e",
        "df92698929c58533e6973a3e010a3c8e4e1d394f1c9c198788b496512c6bb48a",
        "ca5288a4dff112aa34044c2ebdd32d35b2a618421a191dd94e71a2a2867f3abb",
    );

    #[test]
    fn the_wire_matches_the_pinned_vectors() {
        let (mut ini, res) = finished_fixed_handshake();
        let (k1, k2) = ini.dangerously_get_raw_split();
        assert_eq!(
            (hex(&k1), hex(&k2), hex(&ini.get_handshake_hash()[..32])),
            (
                REFERENCE_SPLIT.0.to_string(),
                REFERENCE_SPLIT.1.to_string(),
                REFERENCE_SPLIT.2.to_string()
            )
        );
        let (old_i, _) = ours_and_snows(ini, false);
        let (old_r, _) = ours_and_snows(res, false);
        let (ini, _) = finished_fixed_handshake();
        let (new_i, _) = ours_and_snows(ini, true);
        assert_eq!(
            REFERENCE_VECTORS.len(),
            2 * COUNTERS.len() * LENGTHS.len() + 2
        );
        for &(sender, c, len, want) in REFERENCE_VECTORS {
            let keys = match sender {
                "initiator" => &old_i,
                "responder" => &old_r,
                "initiator+header" => &new_i,
                other => panic!("unknown sender {other}"),
            };
            let ct = keys
                .encrypt(c, &pinned_header(c), &plaintext(len))
                .expect("seals");
            assert_eq!(fingerprint(&ct), want, "{sender}, counter {c}, {len} bytes");
        }
    }

    /// Prints the table `REFERENCE_VECTORS` and `REFERENCE_SPLIT` hold: the
    /// old mode from snow itself (the reference), the new mode's two rows
    /// from this module (there is no other reference for it).
    #[test]
    #[ignore = "prints the pinned tables; run once when they are written"]
    fn print_the_reference_vectors() {
        let (mut ini, res) = finished_fixed_handshake();
        let (k1, k2) = ini.dangerously_get_raw_split();
        println!(
            "const REFERENCE_SPLIT: (&str, &str, &str) = (\n    \"{}\",\n    \"{}\",\n    \"{}\",\n);",
            hex(&k1),
            hex(&k2),
            hex(&ini.get_handshake_hash()[..32])
        );
        let (_, snow_i) = ours_and_snows(ini, false);
        let (_, snow_r) = ours_and_snows(res, false);
        println!("const REFERENCE_VECTORS: &[(&str, u64, usize, &str)] = &[");
        for (sender, snow) in [("initiator", &snow_i), ("responder", &snow_r)] {
            for c in COUNTERS {
                for len in LENGTHS {
                    let pt = plaintext(len);
                    let mut ct = vec![0u8; len + TRANSPORT_TAG_LEN];
                    let n = snow.write_message(c, &pt, &mut ct).expect("snow seals");
                    println!(
                        "    (\"{sender}\", {c}, {len}, \"{}\"),",
                        fingerprint(&ct[..n])
                    );
                }
            }
        }
        let (ini, _) = finished_fixed_handshake();
        let (new_i, _) = ours_and_snows(ini, true);
        for len in [0, 1] {
            let ct = new_i
                .encrypt(1, &pinned_header(1), &plaintext(len))
                .expect("seals");
            println!(
                "    (\"initiator+header\", 1, {len}, \"{}\"),",
                fingerprint(&ct)
            );
        }
        println!("];");
    }

    /// Spec §4.9 (c): with the header in the associated data, changing any
    /// of its 18 bytes fails the tag; without it, the header is not read at
    /// all -- which is the whole point of the change. The two modes do not
    /// open each other's datagrams.
    #[test]
    fn with_the_header_in_the_aad_every_header_byte_is_authenticated() {
        let (ini, res) = finished_fixed_handshake();
        let (with_i, _) = ours_and_snows(ini, true);
        let (with_r, _) = ours_and_snows(res, true);
        let (ini, res) = finished_fixed_handshake();
        let (without_i, _) = ours_and_snows(ini, false);
        let (without_r, _) = ours_and_snows(res, false);
        let c = 7;
        let h = header(c);
        let sealed_with = with_i.encrypt(c, &h, b"payload").expect("seals");
        let sealed_without = without_i.encrypt(c, &h, b"payload").expect("seals");
        assert_eq!(
            with_r.decrypt(c, &h, &sealed_with).expect("opens"),
            b"payload"
        );
        assert_ne!(sealed_with, sealed_without, "the header changes the tag");
        assert!(without_r.decrypt(c, &h, &sealed_with).is_err());
        assert!(with_r.decrypt(c, &h, &sealed_without).is_err());
        for i in 0..h.len() {
            let mut changed = h;
            changed[i] ^= 0x01;
            assert!(
                with_r.decrypt(c, &changed, &sealed_with).is_err(),
                "byte {i} of the header is authenticated"
            );
            assert_eq!(
                without_r
                    .decrypt(c, &changed, &sealed_without)
                    .expect("old mode"),
                b"payload",
                "the old mode does not read byte {i}"
            );
        }
    }

    /// A datagram cut shorter than the tag is refused, not a panic: snow
    /// checked the length itself, the AEAD crate now does.
    #[test]
    fn a_ciphertext_shorter_than_the_tag_is_refused() {
        for header_aad in [false, true] {
            let (_, res) = finished_fixed_handshake();
            let (rx, _) = ours_and_snows(res, header_aad);
            for len in 0..TRANSPORT_TAG_LEN {
                assert!(
                    matches!(
                        rx.decrypt(1, &header(1), &vec![0u8; len]),
                        Err(TransportError::Decrypt)
                    ),
                    "{len} bytes, header_aad {header_aad}"
                );
            }
        }
    }

    /// Spec §4.9: counter 2^64 - 1 is refused both ways, as snow's
    /// `validate_nonce` refuses it; the one before it is fine.
    #[test]
    fn the_last_counter_is_refused_both_ways() {
        let (ini, res) = finished_fixed_handshake();
        let (tx, _) = ours_and_snows(ini, false);
        let (rx, _) = ours_and_snows(res, false);
        assert!(matches!(
            tx.encrypt(u64::MAX, &header(u64::MAX), b"x"),
            Err(TransportError::NonceExhausted)
        ));
        let sealed = tx
            .encrypt(u64::MAX - 1, &header(u64::MAX - 1), b"x")
            .expect("seals");
        assert_eq!(
            rx.decrypt(u64::MAX - 1, &header(u64::MAX - 1), &sealed)
                .expect("opens"),
            b"x"
        );
        assert!(matches!(
            rx.decrypt(u64::MAX, &header(u64::MAX), &sealed),
            Err(TransportError::NonceExhausted)
        ));
    }

    #[test]
    fn ik_handshake_and_transport_roundtrip() {
        let server = generate_keypair();
        let client = generate_keypair();

        let mut ini = Handshake::new_initiator(&client.private, &server.public);
        let mut res = Handshake::new_responder(&server.private);

        let m1 = ini.write_msg(&[]); // e, es, s, ss
        let _ = res.read_msg(&m1).unwrap();
        let m2 = res.write_msg(b"session=42"); // e, ee, se + payload
        let payload = ini.read_msg(&m2).unwrap();

        assert!(ini.is_finished() && res.is_finished());
        assert_eq!(payload, b"session=42");
        // The server learns the client's static key (for the allowlist).
        assert_eq!(res.remote_static().unwrap(), client.public);

        let ck = ini.into_transport(false);
        let sk = res.into_transport(false);
        let ct = ck.encrypt(1, &header(1), b"hello").expect("seals");
        assert_eq!(sk.decrypt(1, &header(1), &ct).unwrap(), b"hello");
        // The same counter in the reverse direction -- an independent
        // direction key.
        let ct2 = sk.encrypt(1, &header(1), b"pong").expect("seals");
        assert_eq!(ck.decrypt(1, &header(1), &ct2).unwrap(), b"pong");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (s, c) = (generate_keypair(), generate_keypair());
        let mut ini = Handshake::new_initiator(&c.private, &s.public);
        let mut res = Handshake::new_responder(&s.private);
        res.read_msg(&ini.write_msg(&[])).unwrap();
        ini.read_msg(&res.write_msg(&[])).unwrap();
        let ck = ini.into_transport(false);
        let sk = res.into_transport(false);
        let mut ct = ck.encrypt(7, &header(7), b"secret").expect("seals");
        ct[0] ^= 0xff;
        assert!(sk.decrypt(7, &header(7), &ct).is_err());
    }

    /// The raw split does not check that the handshake is over, so
    /// `into_transport` does: keys from a half-done handshake would be
    /// derived before the key exchange is complete.
    #[test]
    #[should_panic(expected = "the transport keys are taken after the handshake finishes")]
    fn into_transport_refuses_an_unfinished_handshake() {
        let (s, c) = (generate_keypair(), generate_keypair());
        let mut ini = Handshake::new_initiator(&c.private, &s.public);
        let _msg1 = ini.write_msg(&[]);
        assert!(!ini.is_finished());
        let _ = ini.into_transport(false);
    }

    /// Both sides end the handshake with the SAME hash, and two handshakes
    /// with the same keys still differ (the ephemerals go into it). This is
    /// what the SSH-signature auth layer signs, so uniqueness per session is
    /// the whole point.
    #[test]
    fn handshake_hash_matches_on_both_sides_and_differs_per_session() {
        let server = generate_keypair();
        let client = generate_keypair();

        let run = || {
            let mut ini = Handshake::new_initiator(&client.private, &server.public);
            let mut res = Handshake::new_responder(&server.private);
            let msg1 = ini.write_msg(&[]);
            res.read_msg(&msg1).expect("msg1 is well formed");
            let msg2 = res.write_msg(&[]);
            ini.read_msg(&msg2).expect("msg2 is well formed");
            (ini.handshake_hash(), res.handshake_hash())
        };

        let (a_ini, a_res) = run();
        assert_eq!(a_ini, a_res, "both sides derive the same hash");
        let (b_ini, _) = run();
        assert_ne!(a_ini, b_ini, "a fresh session gets a fresh hash");
    }
}

#[cfg(test)]
mod key_erasure_tests {
    use super::*;

    #[test]
    fn static_private_owner_erases_only_private_bytes() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let mut key = Keypair {
            private: [7; KEY_LEN],
            public: [9; KEY_LEN],
        };
        wipes_on_drop(&key);
        key.zeroize();
        assert_eq!(key.private, [0; KEY_LEN]);
        assert_eq!(key.public, [9; KEY_LEN]);
    }
}
