# The qsh protocol

This document describes what qsh puts on the wire and why it is safe to do
so, in enough detail to check the cryptography or write another client. It
is written from the code, not from the README: every claim below names the
file it came from, and anything the code does not say is not here.

Where the README's "How it works" and "Security" sections answer *why*, this
one answers *how exactly*.

Everything lives in `crates/transport/src` unless stated otherwise. The
files that matter:

| File | What it holds |
|---|---|
| `wire.rs` | datagram header, discovery datagrams, anti-replay window |
| `cookie.rs` | the return-address check under load: cookie secret and load meter |
| `handshake.rs` | Noise IK over `snow`, transport encryption |
| `handshake_payload.rs` | the versioned payloads inside msg1 and msg2 |
| `features.rs` | the negotiable features and the rule that turns them on |
| `conn.rs` | one connection: handshake, streams, liveness, roaming |
| `reliability.rs` | the reliable ordered stream and its frames |
| `paths.rs` | several addresses to one peer, and which to use |
| `channel.rs` | the session control stream: opening channels |
| `auth.rs` | where the client's proof travels and what it commits to |
| `probation.rs` | what an unproven connection may do (nothing) |
| `session_manager.rs` | sessions, tokens, reattach, the session table |
| `shell_frame.rs` | the record envelope used on top of streams |
| `driver_std.rs` | the client's own loop: socket, timers, handshake retransmit |

---

## 1. Wire format

There are three nested layers of framing. From the outside in: the UDP
datagram, the stream frames inside its encrypted payload, and the records
that some streams carry.

### 1.1 The datagram

`wire.rs`. Two header bytes always: a version and a kind.

```
   byte 0     byte 1
  +--------+--------+---------------------------------------------
  | 0x02   | kind   | body, meaning depends on the kind
  +--------+--------+---------------------------------------------
   VERSION
```

`VERSION` is `0x02`. Protocol 1 peers, including the published v0.5.0,
are incompatible: there is no protocol-1 retry or QSH session fallback.
Configured SSH recovery is separate (§2.6). `Kind` is one of:

| Value | Kind | Body |
|---|---|---|
| `0x00` | `HandshakeInit` | the Noise IK first message |
| `0x01` | `HandshakeResp` | the Noise IK second message |
| `0x02` | `Transport` | see below |
| `0x03` | `KeyRequest` | key discovery, unauthenticated |
| `0x04` | `KeyOffer` | the answer to `KeyRequest` |
| `0x05` | `CookieReply` | under load, a cookie for a msg1 (§2.7) |
| `0x06` | `HandshakeInitCookie` | msg1 again, behind a cookie (§2.7) |

A `Transport` datagram — every datagram after the handshake — carries a
fixed 18-byte header, then the AEAD ciphertext with its tag:

```
   0        1        2              10             18
  +--------+--------+--------------+--------------+------------------------+
  | 0x02   | 0x02   | session_id   | counter      | ChaCha20-Poly1305      |
  |        |        | u64, big-end | u64, big-end | ciphertext + 16B tag   |
  +--------+--------+--------------+--------------+------------------------+
  \_____ header: the associated data only with header-aad _____/
```

What the AEAD authenticates besides the ciphertext depends on the connection
(§2.6). With `header-aad` negotiated the whole 18-byte header is the
associated data, so neither the session id nor the counter can be altered
without the tag failing. If `header-aad` is not negotiated, the associated
data is empty: the counter is still protected, because it is the nonce, but
the `session_id` is not authenticated; altering it only sends the datagram
to another session, whose keys do not open it. The nonce is
four zero bytes and then `counter` little-endian, as Noise's
ChaCha20-Poly1305 builds it; it must never repeat within one direction, and
a counter of 2⁶⁴−1 is refused both ways. The two keys come from the Noise
handshake's split (`Handshake::into_transport`: the initiator seals with the
first and opens with the second, the responder the other way round), and
the AEAD is `chacha20poly1305` itself — `snow` runs the handshake and nothing
after it. Each side counts its own outgoing datagrams from 1
(`Connection::new` sets `next_counter: 1`) and the two directions have
separate keys, so both may use the same counter values.

`parse` is the only entry point for network bytes. It rejects a datagram
shorter than two bytes (`TooShort`), a wrong version byte (`BadVersion`), an
unknown kind (`BadKind`), and a `Transport` datagram shorter than 18 bytes
(`TooShort`). Nothing panics on malformed input.

### 1.2 Discovery

Noise IK needs the server's static public key before the client can send
anything, so a client that has never met a server can ask for it.
`encode_key_request` builds `0x02 | 0x03 | 0x01`, then zero-pads to
`KEY_REQUEST_MIN_LEN` = 64 bytes. The answer is
`0x02 | 0x04 | 0x01 | server_pub[32]` — 35 bytes. The request is padded past
the answer deliberately: the amplification factor stays at or below one, so the
port cannot be used to bounce traffic at a spoofed victim. There is a test for
exactly that (`a_discovery_request_is_padded_to_the_size_of_its_answer`).

The server answers only if the request is at least `KEY_REQUEST_MIN_LEN`
long *and* it has a signature verifier configured (`session_manager.rs`,
`handle_datagram`). **Both production daemons have one**: `qshd serve`
always (the `ServerAuth` built by `run_serve_command` in
`qshd/src/serve.rs`), and the SSH-installed `qshd transport-ensure` too (the
`ServerAuth` built by `become_transport_daemon` in `qshd/src/main.rs`, whose
verifier comes from `signature_verifier` — which returns one whenever `HOME`
is set, and a daemon started the normal way always has it, whether or not an
`authorized_keys` file exists to admit anybody). The comment on that
`ServerAuth` names the consequence as a deliberate side effect: this daemon
tells anyone who asks what its public key is. That is what lets a console
client reach a host it has never pinned, at the price of a port scan
learning a fingerprint of the service — which admits nobody, but is real
exposure.

Nothing answers discovery when there is no verifier: a `transport-ensure`
daemon launched without `HOME` (signature login disabled, only the key list
left), and the diagnostic `transport-echo` / `transport-shell` commands,
which do not run a `SessionManager` at all and so have no discovery
responder in the first place.

The answer is unauthenticated by construction; §9 says what follows from
that.

### 1.3 Anti-replay

`wire.rs`, `ReplayWindow`. A bitmap of 32 768 positions kept as a ring of
512 64-bit words, as in RFC 6479: moving the maximum forward zeroes whole
words and never shifts bits. One word is held in reserve, so the window in
effect is `REPLAY_WINDOW` = 32 704 positions behind the highest counter
accepted so far:

- the first counter of a session is accepted and becomes the maximum;
- a counter above the maximum is accepted and moves the window;
- a counter already seen -- the maximum included -- is a replay: rejected;
- a counter at most 32 704 behind, not yet seen, is accepted;
- anything further behind is rejected as too old.

Why that size. The counter is one per direction for the whole connection,
whatever road a datagram takes, so an answer over a fast spare road
overtakes everything still on its way over a slow one. The window has to
cover the datagrams sent during the difference of the two round trips. That
difference is bounded by the 3 s ceiling road liveness keeps
(`RTO_CEILING`: a PING older than that, and a check unanswered for
`PROBE_TIMEOUT`, count against the road; the retransmit timeout itself may
grow to 15 s under a queue, but a road slower than 3 s reads as unanswered
anyway) -- and 32 704 datagrams in 3 s is about 10 900
datagrams/s, some 11 MB/s in 1 KiB segments, above what one window in flight
carries over a mobile link. It costs 4 KiB per connection.

Each side checks only what it receives: a peer running an older build
(64 positions) still drops datagrams of ours that its fast spare's answers
overtook. The two directions are fixed independently, and fully only once
both ends run this version.

`is_new_max` answers "would this counter become the new maximum" *without*
mutating, and must be called before `accept`. It is the address-migration
condition (§5): a packet that is merely fresh-in-window does not move the
session.

### 1.4 Stream frames

`reliability.rs`. Inside the decrypted payload sit one or more frames. Each
is a type byte followed by big-endian fields:

```
  0x01 ACK             stream_id(1)  cum_ack(u32)
  0x02 DATA            stream_id(1)  offset(u32)  len(u16)  payload[len]
  0x03 PING            token(u32)
  0x04 PONG            token(u32)
  0x05 CLOSE           stream_id(1)
  0x06 RESET           stream_id(1)  new_offset(u32)
  0x07 PATH_PROBE      token(u32)
  0x08 PATH_PROBE_ACK  token(u32)
  0x09 CREDIT          stream_id(1)  limit(u32)
```

`CREDIT` goes only to a peer that agreed `stream-credit` (§2.6, §7): a parser
from before it would stop at the unknown type and drop the rest of the
datagram.

`decode_all` parses frames back to back and is written against untrusted
input: a truncated frame or an unknown type stops the parse and returns
whatever was already read, rather than failing or panicking. The receiver
therefore accepts several frames in one datagram, and this
implementation packs them: a datagram is at most `MAX_DATAGRAM` = 1200
bytes on the wire — QUIC's minimum, which IPv6's 1280-byte floor and
ordinary tunnels carry whole — so 1 166 bytes of frames; a full `DATA`
segment (1 032 bytes) leaves room for 22 six-byte frames. Frames that must
stay in order (`DATA` of one stream; a `Reset` and the repaint behind it)
keep it; `ACK` and `CREDIT`, cumulative and idempotent, fill whatever room
is left (§7, Acknowledgements). **A road check and its answer always travel
alone**: a receiver takes a datagram of nothing but `PATH_PROBE` /
`PATH_PROBE_ACK` frames as probing (§5), and one built before packing would
take a check packed with ordinary frames for an ordinary datagram and move
the session to its source. A peer built before packing sends one frame a
datagram and understands packed ones: its `decode_all` always read several.

`DATA` payloads are chunked at `MAX_SEGMENT_SIZE` = 1024 bytes.

### 1.5 Records on a stream

`shell_frame.rs`. A stream is a byte stream; the layers above it frame their
own messages as records:

```
  type(1) | len(u32 big-endian) | payload[len]
```

`RecordDeframer` buffers an unfinished tail across chunk boundaries. Because
the length is explicit, an unknown record type can be skipped without losing
sync — which is what lets both peers ignore record kinds they do not know.

Two record vocabularies use this envelope: the channel output stream's
`DATA` (0), `ECHO_ACK` (1), `GEOMETRY` (2), and `OUTPUT_GAP` (3), and the
session control stream's (§8). `ECHO_ACK` carries a `u64` big-endian count
of input bytes the server has consumed. The authentication record has framing of its own (§3).

A record's length is bounded by what its stream carries: 64 KiB on the
session-control stream (`CONTROL_RECORD_MAX`; its longest record, a
`CHANNEL_SNAPSHOT` payload is at most 36,386 bytes, checked before
allocation; see §8), 64 MiB on any other (`RECORD_MAX`; the longest is a repaint). A
reader that meets a longer declared length stops reading that stream — the
length that would find the next record cannot be trusted — and drops the
rest; the daemon logs it once per connection, and the console client
reports it too. A new connection's streams start afresh.

---

## 2. Handshake

`handshake.rs`, `handshake_payload.rs`, and `Connection::accept` /
`on_handshake_resp` in `conn.rs`.

The parameter string is fixed in code:

```
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

The handshake uses X25519 for agreement and ChaCha20-Poly1305 for
authenticated encryption; hashes use BLAKE2s. The implementation is `snow`. IK means the
initiator knows the responder's static public key up front and sends its own
static key inside the first message.

Two messages, one round trip:

```
  client                                                     server
    |                                                           |
    |   [KeyRequest]  (only on first contact, unauthenticated)   |
    | --------------------------------------------------------> |
    |   [KeyOffer: server static public key]                     |
    | <-------------------------------------------------------- |
    |                                                           |
    |   HandshakeInit: Noise msg1 (e, es, s, ss) + msg1 payload  |
    | --------------------------------------------------------> |
    |                                 reads the client's static  |
    |                                 key, applies the policy,   |
    |                                 mints a random session_id  |
    |   HandshakeResp: Noise msg2 (e, ee, se) + msg2 payload     |
    | <-------------------------------------------------------- |
    |                                                           |
    |   Transport datagrams, both directions, from here on       |
    |<========================================================> |
```

### 2.1 What msg1 carries

`encode_msg1`, 23 bytes:

```
  HS_VERSION(0x02) | start_kind(1) | token(16) | method(1)
  | offered(u32, big-endian)
```

- `start_kind`: `Cold` = `0x00`, `Warm` = `0x01`. Cold asks for a fresh
  session; Warm asks to return to the one this token names (§4).
- `token`: 16 bytes the *client* chooses. It identifies the session, not the
  connection. `SESSION_TOKEN_LEN` = 16.
- `method`: which authentication policy the client announces —
  `Allowlist` = `0x00`, `SshSignature` = `0x01` (§3).
- `offered`: the features the client can use (§2.6).

The payload travels inside the Noise message, so the token is readable only
after msg1 decrypts. `session_manager.rs` builds the whole reattach decision
inside the `accept` call for that reason: it is the only moment where the
token is available and msg2 has not been written yet.

`parse_msg1` requires `HS_VERSION = 2`. Within that version, the generic
codec accepts an 18-byte payload without the method and reads it as `Allowlist`;
a payload shorter than 23 bytes offers no features. Current encoders always
write both fields. These shortened forms do not provide protocol-1 compatibility
and cannot establish an application channel session, which requires the
`channel-geometry` feature (§2.6).

### 2.2 What msg2 carries

`encode_msg2`, 30 bytes:

```
  HS_VERSION(0x02) | session_id(8, big-endian) | resumed(1) | nonce(16)
  | enabled(u32, big-endian)
```

`session_id` is a fresh random `u64` (`rand::thread_rng().gen()`) minted per
handshake, and is what the datagram header carries afterwards. `resumed`
says whether this handshake landed on the session the client asked for by
token rather than on a new one. The client cannot work that out for itself:
an unknown token is answered with a new session and no complaint, which is
indistinguishable from a resume unless the server says so. `nonce` is a
fresh `AUTH_NONCE_LEN` = 16-byte value handed to this handshake alone; a
client that goes on to send a version 2 AUTH record echoes it back under
the signature (§3.2.1), so a proof made for one handshake cannot be
presented for another. `enabled` is what this connection uses (§2.6).

`parse_msg2` also requires `HS_VERSION = 2`. Its generic codec accepts a
9-byte payload as `resumed: false`; a payload shorter than 26 bytes has no
nonce, and one shorter than 30 bytes enables no features. Application channel
clients reject the missing mandatory feature before becoming Live or sending
queued application output. These codec defaults are not a way to connect to a
protocol-1 daemon. AUTH record versions in §3 are a separate format from the
wire and handshake versions.

The `resumed` flag is provisional on the signature path. It is computed from the decision resolved *inside* `accept` — by the
`resolve_for_msg2` closure `handle_datagram` passes it — because msg2 has to
be written there. But the decision actually applied is resolved again after
probation ends, in `on_probation_ended`, against the table as it stands
then. A round trip has passed; the two can differ.

### 2.3 What the server does with msg1

`Connection::accept`, in order, with `Rejected` at every failure and no reply
of any kind:

1. read the Noise message; a malformed one is a rejection;
2. take the client's static public key out of the handshake state;
3. `AuthPolicy::admits` on that key (§3);
4. parse the msg1 payload;
5. compare the announced `method` against the policy **this `accept` call
   was given** — a mismatch is a rejection, so neither path can be silently
   downgraded into the other. A daemon may run both policies, and then
   `handle_datagram`'s `HandshakeInit` arm makes two `accept` calls, one per
   policy: the client's announced method is what decides which succeeds;
6. negotiate features (§2.6) and reject if any configured required bit is
   missing, before calling the session resolver;
7. ask the router whether this token resumes an existing session;
8. mint the `session_id`, write msg2 with the negotiated features, take the
   transport keys in the agreed mode, record the source address, go `Live`.

There is a *second* server-side entry point, `Connection::on_handshake_init`,
reached through `on_datagram` rather than `accept`. It refuses
`AuthPolicy::SshSignature` outright and closes: nothing there could wait for
a proof that arrives afterwards, and `admits` passes for any key under that
policy, so running it there would mean admitting everyone. The refusal is
unreachable today; it is pinned so a future refactor cannot turn it into an
authentication bypass with no symptom. That entry point decides the features
by the same rule; a msg1 whose payload it cannot read offers nothing. It also
rejects missing required features before creating a Live connection.

### 2.4 Retransmission

`driver_std.rs`. During `Connecting` the core has no timers of its own, so
the driver retransmits: every `HANDSHAKE_RETRANSMIT` = 500 ms it re-sends the
**stored first msg1 datagram, byte for byte**, until `Live` or `Closed`.
Rebuilding the initiator would mint a fresh Noise ephemeral and thus a
different msg1, which the server would read as a new handshake rather than a
retransmit — see `ResendMsg2` in §4.

A daemon under load may answer msg1 with a cookie instead (§2.7). The client
then sends the same msg1 behind the cookie at once, and the next retransmit
carries the cookie too; from then on the retransmits take turns — the plain
msg1, then the msg1 behind the newest cookie it was handed, and so on
(`Connection::retransmit_handshake`). The plain turns are there because a
cookie need not come from the daemon: a party on the path that sees msg1 can
answer it with one, and a compatible peer without cookie support would drop
every msg1 behind one (§2.7, "Peers without cookies"). Against a daemon under load a plain turn costs a
cookie reply and nothing else. A second cookie waits for its turn rather than
going out at once, so a cookie that keeps failing (a NAT that changes the
port on every packet) cannot turn into a ping-pong. The daemon takes the
cookie off before it compares a retransmit, so `ResendMsg2` still sees the
bytes of the first msg1. A handshake that took a cookie seeds no round-trip
estimate (§5.1): two different msg1 datagrams were out, and msg2 may answer
either.

### 2.5 The handshake hash

`Handshake::handshake_hash` returns `snow`'s handshake hash `h`, 32 bytes.
Both sides derive the same value; it commits to both static keys and both
ephemerals, so it is unique per session. Two handshakes between the same
pair of keys produce different hashes — there is a test for that
(`handshake_hash_matches_on_both_sides_and_differs_per_session`). It must be
read before `into_transport` consumes the state. §3 is what it is for.

### 2.6 Negotiating features

`features.rs`, `handshake_payload.rs`.

A connection's optional features are agreed in its handshake, as 32 bits:
msg1 says what the client can do (`offered`, §2.1), msg2 what this
connection will do (`enabled`, §2.2).

| Bit | Name | Meaning |
|---|---|---|
| 0 (`0x0000_0001`) | `header-aad` | the 18-byte datagram header is the AEAD's associated data (§1.1) |
| 1 (`0x0000_0002`) | `stream-credit` | `CREDIT` frames and per-stream limits (§7) |
| 2 (`0x0000_0004`) | `offset-wrap` | stream offsets modulo 2³² (§7) |
| 3 (`0x0000_0008`) | `auth-accepted` | reserved; not advertised or enabled |
| 4 (`0x0000_0010`) | `channel-geometry` | ordered geometry and atomic channel lifecycle discovery; required by application channel peers |
| 5–31 | — | reserved, sent as zero |

- A client offers what it implements (`Features::SUPPORTED`).
- A server turns a bit on exactly when msg1 offered it, its configuration
  allows it, and it implements it, and says so in msg2.
- Each field is read only when all four bytes are there; a shorter payload
  offers, or enables, nothing. Bits a side does not know are ignored where
  they are offered; bytes after either field are ignored, for fields not
  invented yet.

Wire, handshake and channel protocol versions are all **2**. The feature
fields are authenticated by Noise; negotiation remains the intersection of
what the client offers, the server allows and this build implements. Application
channel clients and daemons require `channel-geometry`: the server checks before
session resolution/allocation or backend attachment, and the client before Live and
queued application output. Missing geometry is a protocol failure, not a silent
resize fallback. Bit 3 remains unadvertised: geometry or `ABOUT` is not an
explicit post-proof authentication acceptance message. Generic transport-only
profiles can explicitly require `Features::NONE`; this does not relax the
application channel profile.

`Features::SUPPORTED` is `0x17`: header AAD, credits, offset wrapping and channel
geometry. Protocol 1 datagrams are ignored at the outer parser; silence alone
does not identify a peer's version. The CLI reports that protocol 2 is required
when no compatible reply arrives. Configured SSH installation/recovery remains
a separate path, not a protocol-1 QSH session.

- A client that finds a bit in msg2 it did not offer treats msg2 as a
  protocol violation: `Event::UnofferedFeatureEnabled`, a line on stderr
  (`server enabled a transport feature it was not offered: 0x…`), and the
  connection closes — reading msg2 spent the Noise state, so there is nothing
  to wait for.
- An authenticated msg2 with an invalid handshake version/shape reports
  `Event::InvalidHandshakeResponse`; missing required bits report
  `Event::MissingRequiredFeatures`. The standard driver exposes these as typed
  protocol failures. The CLI ends that handshake attempt and key loop instead
  of trying another key or rediscovering the key at that address; its ordinary
  configured SSH/other-address recovery remains separate.
- The decision is a function of msg1 and the configuration, so a
  retransmitted msg1, and its twin that went through probation on its own,
  get the same answer; the server's cached msg2 (`ResendMsg2`, §4) carries
  it too.
- The set holds for the whole connection; a warm reconnect is a new
  handshake and agrees afresh.
- The first transport datagram either side sends is already in the agreed
  mode: the server switches as it writes msg2, the client as it reads it.

What a connection agreed is visible: the daemon logs
`session <id>: transport features <names>` for each connection a session
binds; `qshd self-check` lists what the build
implements (`transport_features`); `qsh --verbose` writes
`transport features: …` to its log. Hosts can read the negotiated features
through `Connection::features` or `StdClient::features`.

### 2.7 Proving the return address under load

`cookie.rs`; `handle_datagram` in `session_manager.rs`;
`Connection::on_cookie_reply` in `conn.rs`.

A `HandshakeInit` costs the daemon Noise's X25519 work and, on the signature
path, a probation seat (§3.3) — both before anything proves that its sender
receives at the address it names. Under load the daemon asks for that proof
first, the way WireGuard's cookie reply and QUIC's Retry do.

**Load.** The daemon is under load while it has received more than 64
handshake datagrams (`HandshakeInit` and `HandshakeInitCookie` alike, whatever
became of them) in the current one-second window or the one before
(`LOAD_HANDSHAKES_PER_WINDOW`, `LOAD_WINDOW`), or more than half of the 128
probation seats are taken (`LOAD_PROBATION_SEATS` = 64). Counting datagrams
received rather than Noise work done keeps a flood counted while its cookies
are being answered. The daemon logs the start of load
(`WARN  transport: under load: …`) and its end (`INFO  transport: load is over: …`) — the end once
load has stayed off for 10 s (`LOAD_LOG_SETTLE`), at the next handshake
datagram, so that a load flickering at its threshold is one episode in the
log rather than two lines per flicker.

**Under load** a `HandshakeInit` gets this answer and nothing else:

    0x02 | 0x05 | 0x01 | echo(16) | cookie(16)          -- 35 bytes

`echo` is the first 16 bytes of the msg1's ephemeral key. `cookie` is keyed
BLAKE2s-128 over `"qsh cookie v1" | source address (16 bytes, IPv4 mapped to
IPv6) | source port (u16, big-endian) | the msg1's ephemeral key (32 bytes)`,
under the daemon's cookie secret: 32 random bytes, replaced every 120 s
(`COOKIE_ROTATION`). A cookie made under the current secret or the one before
it is accepted, so it lives two to four minutes, and a restarted or updated
daemon honours none of the old ones.

The client takes the reply only while its handshake is under way, only from
the address its msg1 went to, and only if `echo` is its own; then it sends
the same msg1 behind the cookie (`HandshakeInitCookie`):

    0x02 | 0x06 | cookie(16) | Noise msg1

and its retransmits carry the cookie in turn with the plain msg1 (§2.4). A
msg1 behind a cookie valid for its source and its ephemeral key is worked on,
within its source's rate (below), and the per-source probation cap (§3.3)
then counts addresses that really receive. An invalid cookie — a NAT that
moved the client to another port, an expired secret — is answered with a
fresh one under load, and ignored without it.

**A rate for proven sources.** A cookie binds one source and one msg1, not
one datagram: the same msg1 behind it may be sent again — a retransmit is
exactly that — and each copy that reaches `accept` costs a Noise handshake.
So while the load lasts the daemon also holds each proven source to 20
handshakes a second after a burst of 5 (`PROVEN_PER_SECOND`, `PROVEN_BURST`:
WireGuard's numbers and its token bucket) and drops the rest in silence, for
one MAC each. A source is an IPv4 address, or an IPv6 /64 — what one host is
handed. Only a valid cookie is charged, so a flood forged in a source's name
costs that source nothing. The table holds 8192 sources
(`PROVEN_RATE_SOURCES`); a new one past that is dropped until the table is
swept of sources idle for 250 ms, the time a spent budget takes to fill
again. An honest client usually needs one proven msg1, so twenty clients
behind one address get in each second — but the budget is the address's, not
a client's: anyone behind it spends it too (a neighbour behind the same
carrier-grade NAT, with cookies of its own), and so can a party on the path
that sends a client's proven msg1 again in the client's name.

**What it costs.** The answer is 35 bytes against at least 98 for the
smallest msg1 the daemon answers at all (`MIN_MSG1_BODY` = 96 bytes of body;
a shorter handshake datagram is dropped under any load) and 121 for the msg1
this build's clients send: a forged source gets back at most 36 % of what was
sent in its name. Per datagram the daemon computes at most three MACs (one
to mint a cookie, up to two to check one against both secrets) and builds
the answer — no Noise work, no nonce, no seat. An honest new client pays one
round trip, and only while the load lasts.

**Peers without cookies.** The following describes the generic cookie mechanism,
not interoperability with protocol-1 binaries. A compatible client without cookie
support behaves like the pre-cookie implementation.

**Client side.** Such a client drops kind `0x05` as unknown (`BadKind`): it keeps sending plain msg1 every 500 ms
and is refused until the load is over — at least a second after a flood
stops. That is the price of the defence, paid only under load — and load is
cheap to cause: 65 forged msg1s a second, about 6.4 KB/s, keep it on for as
long as they last.

**Server side.** A compatible daemon without cookie support never sends `0x05`
and drops `0x06` (`BadKind`). But a cookie reply need not come from the daemon: a
party on the path that sees msg1 — and so its echo — can answer it with a
cookie in the daemon's name, and the client sends `0x06` to a daemon that
drops it. Were every retransmit behind that cookie, a lost first exchange
(msg1 or msg2) would keep the client out for good. The retransmits take
turns with the plain msg1 instead (§2.4), so that daemon sees msg1 again
at the second retransmit after the cookie, a second or so later.

**What it does not do.**

- *A party on the path can keep a new client out while the load lasts.* It
  sees msg1 and so its echo, and can answer each of the client's msg1s with
  a cookie of its own before the daemon's arrives: the client carries the
  forged cookie, the daemon answers it with a fresh one, and the next
  forgery replaces that. Most such parties could drop the client's datagrams
  to the same effect; one that can only inject — a mirrored port, a shared
  radio — gains this from the cookie. WireGuard closes it by sealing its
  cookie reply under a key from the responder's static public key, which
  only its peers know. qsh does not, and that would not help here: both
  production daemons hand their static key to anyone who asks (discovery,
  §1.2) — `qshd serve` and the system mode always, `transport-ensure`
  whenever it was started with `HOME` — so such a party could seal a forged
  reply as well as the daemon.
- *A daemon that answers from another address is refused under load.* The
  client takes a cookie only from the address its msg1 went to. A daemon on
  a host with several addresses whose replies leave from another one than
  the client dialled (a secondary address, a virtual IP) has its cookies
  ignored — although its msg2 would be taken, since msg2 is accepted from
  any source — and so admits no new client while it is under load. Without
  load it connects as before.

The diagnostic `transport-echo` and `transport-shell` servers have no such
check: they serve one client and hold no probation table.

---

## 3. Authentication

Two policies, `AuthPolicy` in `conn.rs`. They differ in *what counts as
proof* and *when it arrives*.

### 3.1 `AuthPolicy::Allowlist(Vec<[u8; 32]>)`

Only the listed client static keys may complete the handshake. The key
itself is the proof, because it got onto the list over a channel that was
already trusted: the daemon started over SSH is handed the client's public
key on its command line (`transport-ensure --client-pubkey`), and its control
socket accepts `ADD-CLIENT` to add one while it runs, which is how a second
`transport-ensure` hands its key to the daemon already up
(`qshd/src/control.rs`, `transport_daemon::apply_add_client`).
The list is in memory only.

Under this policy a handshake binds immediately — `accept` succeeds and the
manager goes straight to its session decision (§4).

The list is self-cleaning. When a session ends, the manager scrubs that
connection's key off the shared allowlist (`remove_from_allowlist` in
`session_manager.rs`), whether the backend was torn down or merely retained.

**Who uses it:** only the `qshd transport-ensure` daemon, which is started
over SSH by `qsh` for an address marked `,ssh`. `qshd serve`
starts with an empty allowlist and keeps it empty (again the `ServerAuth` in
`run_serve_command`), so nothing can ever be admitted by key there.

The console client uses it after `,ssh` brings a `transport-ensure` daemon
up (`crates/bringup`). One Noise static key serves the whole process
(`cli/src/main.rs`); its public half goes into `--client-pubkey`, and the
qsh login right after the SSH step runs under `AuthPolicy::Allowlist`
(`Login::Allowlist` in `cli/src/connect.rs`, `on_the_list` in
`cli/src/climb.rs`). The first qsh login at an address, before any SSH, still
signs. The key is scrubbed when the connection ends (above), and a
reconnect climbs the same ladder: a signature first, then the SSH step,
which puts the key back on the list.

#### 3.1.1 A daemon may run both gates at once

The `ServerAuth` type (`session_manager.rs`) carries an allowlist **and** an
optional verifier, and `handle_datagram`'s `HandshakeInit` arm tries the
allowlist policy first, then the signature policy if a verifier is
configured. Which one applies is decided by the method byte the client
announced inside msg1 (§2.3, step 5).

That is not a leftover; it is the point. The `transport-ensure` daemon runs
both: on the SSH bootstrap that starts it, the client's key goes straight onto
the allowlist, and a client reaching the same daemon directly proves itself
by signature against the same `~/.ssh/authorized_keys` that `serve`
checks — `become_transport_daemon` fills in both fields. This lets clients
using different authentication methods share one daemon and port. `qsh` can
reach both `qshd serve` and `transport-ensure` daemons.

The same gate allows a client to skip SSH when a `transport-ensure` daemon
is already running and the client's SSH key is in `authorized_keys`. The
allowlist still admits the one-time Noise key registered by an SSH bootstrap;
a direct signed login does not depend on that entry.

It widens nothing, and the code says why: whoever can sign with a key in
`authorized_keys` can already log in over SSH and start anything at all on
that host, this daemon included.

### 3.2 `AuthPolicy::SshSignature`

Any static key completes the handshake — the client's Noise key proves
nothing and is deliberately throwaway (`cli/src/main.rs` mints a fresh one
per launch). The proof is an SSH signature, sent right after the handshake.

`auth.rs` defines exactly three things and no more: where the proof travels,
what it commits to, and how it is framed.

- **Where**: `AUTH_STREAM` = 15. This stream belongs to the session layer and
  never reaches a backend — the probation task consumes it, and the bridge
  drops anything that arrives on it afterwards (`drain_events` in
  `session_manager.rs`).
- **What**: which challenge is signed depends on the record's version
  (§3.2.1). A version 1 record signs `auth_challenge(handshake_hash)` = the
  ASCII domain string `AUTH_DOMAIN` = `"qsh-auth-v1"` followed by this
  session's 32-byte handshake hash. The domain prefix is there because an
  agent signs whatever it is asked to: without it, a signature taken here
  would be reusable elsewhere, and someone else's signature reusable here.
  Both trait definitions (`AuthSigner`, `AuthVerifier`) say in their doc
  comments that implementations MUST sign and verify over the challenge
  their record's version calls for (`record_challenge`, which dispatches to
  `auth_challenge` or `auth_challenge_v2`), never the bare hash — a signer
  and a verifier that both made that mistake would still interoperate,
  silently discarding the separation.
- **How**: `version(1) | key_len(u16 BE) | key | sig_len(u16 BE) | sig` for
  a version 1 record (`AUTH_RECORD_VERSION` = `0x01`); a version 2 one
  (§3.2.1) inserts a nonce and a login between the version byte and that
  same key/signature tail. `key` is the standard SSH wire encoding (the
  same bytes that sit base64-encoded in `authorized_keys`) and `sig` is an
  SSH signature blob, which names its own algorithm. A field too large for
  its `u16` length is an error, not a truncation.

`AUTH_DEADLINE` = 5 s bounds how long a connection may stay unproven.

**Verification** is `sshauth::verify::AuthorizedKeysVerifier`
(`crates/sshauth/src/verify.rs`):

1. classify the *signature's* algorithm. `ed25519`, `ecdsa` on nistp256 and
   nistp384, and RSA with a hash (`rsa-sha2-256` / `rsa-sha2-512`) are
   accepted. Bare `ssh-rsa` — RSA with SHA-1 — is refused. nistp521 is
   refused with a distinct "not compiled in" error, because no crypto
   backend for it is linked;
2. **verify the signature before touching the file.** An unverified key is
   just bytes someone sent; matching it against `authorized_keys` first
   would leak whether that key is listed, and would let an unauthenticated
   peer make the daemon read the filesystem at all;
3. then check `authorized_keys`, re-read on every attempt so a key added
   while the daemon runs takes effect at once.

The `authorized_keys` reading is deliberately stricter than OpenSSH's: the
first line naming a key decides, and a line carrying **any** options
(`command=`, `from=`, `restrict`, …) refuses that key rather than applying
the options. qsh cannot honour those options, so refusing is the only honest
answer — see §9.

On success the verifier returns a short identity for the log (the key's
SHA-256 fingerprint), never anything secret.

#### 3.2.1 Version 2: naming an account

A record's `v2` field is `Some(AuthV2)` for a version 2 record, `None` for
a version 1 one (`AuthRecord` in `auth.rs`) — that field is the whole
difference; where the proof travels and how the key/signature tail is
framed does not change.

`AuthV2` carries two fields, in this order both on the wire and under the
signature:

- `nonce`: `AUTH_NONCE_LEN` = 16 bytes, the value this handshake's msg2
  carried (§2.2), echoed back so a proof made for one handshake cannot be
  presented for another.
- `login`: 1 to `AUTH_LOGIN_MAX` = 255 bytes of UTF-8, with no `/` and no
  NUL (`login_is_usable`, shared by the encoder and the parser so the two
  cannot drift apart on what they accept). It is checked this strictly
  because it eventually reaches a `getpwnam` on the far side: a `/` would
  turn a name into a path, a NUL would truncate it inside C.

**Wire framing** (`encode_auth_record`/`parse_auth_record`):
`version(1)=0x02 | nonce(16) | login_len(u8) | login | key_len(u16 BE) |
key | sig_len(u16 BE) | sig` — the nonce and login sit between the version
byte and the same key/signature tail a version 1 record ends with.
`login_len` is a single byte because `AUTH_LOGIN_MAX` fits in one.

**What it commits to**: `auth_challenge_v2(handshake_hash, v2)` = the ASCII
domain string `AUTH_DOMAIN_V2` = `"qsh-auth-v2"`, then the 32-byte
handshake hash, then the nonce, then the login bytes with no length of
their own — everything ahead of the login is fixed-width, so the split
stays unambiguous without one. `AUTH_DOMAIN_V2` is a distinct string from
`AUTH_DOMAIN` on purpose: a verifier that accepted a version 1 signature
over a version 2 record would be taking the login on the client's word
alone, with no cryptography behind it.

Before a v2 record's signature is even checked, the probation gate
(`AuthGate::feed` in `probation.rs`) compares its nonce against the one
issued for *this* handshake and refuses the record — `AuthError::BadRecord`
— on any mismatch, so a proof lifted from another handshake never reaches
the verifier at all.

**Which version a client sends** is decided by `sshauth::v2_fields`, from
whether msg2 carried a nonce: no nonce means
a version 1 record, because there is nowhere in it to put a login. A nonce
present means a version 2 record — and requires a login already configured
on the signer (`with_login`, which the CLI calls for every candidate it
builds, with the login `args::resolve_login` settled on). A nonce with no
login configured is a hard `AuthError::Backend`, not a silent fall-back to
version 1: a server that sent a nonce expects a login, and falling back
would hand it a record it must refuse instead of an error the user can
act on.

**What today's personal-mode verifier does with the login**:
`AuthorizedKeysVerifier` (`crates/sshauth/src/verify.rs`), the
`AuthVerifier` `qshd serve` runs in production, accepts a version 2
record and does not check its login against the single account it
serves — its own doc comment explains why: this daemon has exactly one
account to offer, so a login naming another selects nothing, and
refusing the claim would only break a client that guessed its own
account's name differently. The `Principal` it returns always names that
one account, whatever the record claimed.

A second production `AuthVerifier`, `HelperAuth` (`qshd/src/helper/spawner.rs`),
is what `qshd serve --system` runs instead: it does check the login,
against a real account resolved by the privileged helper through
`getpwnam` — see `docs/qshd-service.md`'s "System mode" section for the
daemon-level picture, this document's job is only the wire format above.

### 3.3 Probation

`probation.rs`. A signature handshake does not become a session; it becomes
a probation.

```
  HandshakeInit
       |
       v
  Connection::accept  --- rejected ---> nothing sent, nothing recorded
       |
       | accepted, policy = SshSignature
       v
  +----------------------------------------------------+
  | PROBATION                                          |
  |  - a task owns the Connection and answers its      |
  |    transport chatter (ACKs, PINGs, retransmits)    |
  |  - the manager registers ONLY the datagram route   |
  |  - the backend table is not touched at all         |
  +----------------------------------------------------+
       |                                   |
       | AUTH record verifies              | bad record / closed / 5 s
       v                                   v
  the manager resolves the session    route dropped, task exits,
  decision (§4) against the table     nothing else happened
  as it stands NOW, and binds
```

What this buys, in the words of the module's own doc: an unproven peer
cannot repoint another device's route, overwrite its client key, scrub that
key off the shared allowlist, or evict a retained backend — **because it
never reaches the code that does any of those things**. The guarantee is
structural, not a check repeated at each write site.

Its bounds, all of them real numbers in the code:

| Constant | Value | What it bounds |
|---|---|---|
| `MAX_PROBATION` | 128 | unproven connections at once, all sources |
| `MAX_PROBATION_PER_SOURCE` | 16 | how many of those one source group may hold |
| `AUTH_RECORD_MAX` | 8 KiB | the record-reassembly buffer |
| `EARLY_DATA_MAX` | 64 KiB | pre-proof stream data held for replay |
| `PROBATION_UNDELIVERED_MAX` | 64 KiB | out-of-order stream data held, all streams together |
| `AUTH_DEADLINE` | 5 s | how long a slot may be held |

Over the cap, a handshake is dropped in silence: there is nothing to evict,
because nothing there belongs to anyone yet. The per-source cap uses the
cookie rate limiter's source groups (§2.7):
one IPv4 host (including its IPv4-mapped IPv6 form), or one native IPv6 /64.
Ports, IPv6 host bits and scope IDs do not create extra budgets.
It exists because the global cap alone is exhaustible by one address, and a
full table is a lockout — every sign-in and every warm reattach passes
through it.

Data a client sends before its proof lands is collected and replayed to the
backend after binding, in arrival order, strictly after the backend hears
its session start. It is accounted by *cost*, not payload:
`EARLY_ENTRY_COST` is charged per collected chunk, because one 64 KiB
datagram can deliver thousands of one-byte stream frames at distinct offsets
and counting payload alone would under-account by orders of magnitude.
Crossing `EARLY_DATA_MAX` refuses the whole connection rather than dropping
the excess.

Nothing that arrives during probation is lost. The probation task does not
read its datagram queue while a record is being verified (the verifier runs
off the task), and after the verdict the manager still needs a turn of its
loop to bind the connection. So the queue goes with the connection: a cold
create adopts the provisional route and its queue as the bridge's own, and
the bridge reads them in order; a warm reattach empties the queue into the
`Attach` it hands the running bridge, which runs those datagrams through the
new connection before reading anything else. A road check sent while the
proof is verified is answered.

### 3.4 There is no "accepted" or "refused" on the wire

A refused proof is not answered with an error. The probation task exits, the
manager drops the route, and the server simply stops answering. An attacker
probing keys therefore learns nothing from the failure mode.
`cli/src/connect.rs` infers the outcome instead — from whether the handshake
completed, whether any data arrived, whether the link is live now, and how
long it has been — and documents the one residual ambiguity it accepts (an
accepted session whose shell prints nothing and then exits reads as a
refusal).

One answer does precede every check: under load (§2.7) a msg1 is answered
with a cookie before anything is read from it. It says the daemon is busy,
nothing about whether a key would be accepted; and a proven msg1 past its
source's rate is dropped in silence, like any refusal.

---

## 4. Sessions

`session_manager.rs`. A session on the server is a **backend** — a running
process or set of processes, with its terminal state — plus the routing that
reaches it. Two keys address it:

- the **token**, 16 bytes chosen by the client, one entry per device in the
  `backends` map. This is the identity that survives disconnection.
- the **`session_id`**, a random `u64` minted by the server per handshake,
  one entry in the `sessions` map. This is the datagram demultiplexer, and
  it changes on every handshake.

```
  backends:  token ---> BackendEntry { session_id, client_key,
                                       last_msg1_body, msg2, state, ... }
  sessions:  session_id ---> channel to the task that owns the Connection
  probation: session_id ---> its canonical source group, and the token
                             its msg1 named
```

A `Transport` datagram is delivered to the one task whose `session_id`
matches, and dropped if there is none.

### 4.1 What a repeated token means

`Router::resolve`:

| Existing entry? | msg1 body | `start_kind` | Decision |
|---|---|---|---|
| none | — | — | `ColdCreate` — spawn a fresh backend |
| yes | byte-identical to the one that bound it | — | `ResendMsg2` |
| yes | different | `Warm` | `WarmReattach` |
| yes | different | `Cold` | `ColdReplace` — tear down, create fresh |

`ResendMsg2` is the retransmit case, and it is why §2.4 insists on a
byte-identical retransmit: an identical body means the same Noise ephemeral,
which means the client never saw msg2. The server re-sends the **original**
msg2, with the original `session_id`, and touches nothing else. Minting a
new `session_id` there would repoint the route while the client — already
live on the first msg2 — stayed on the old one, wedging it.

`WarmReattach` swaps the new `Connection` into the still-running bridge:
the backend is not respawned, `ResumeReset` goes to it, the route is
repointed to the new `session_id`, and msg2 says `resumed: true`. Each
backend has exactly one backend task and one bridge task for its whole life;
only the connection they drive is swapped.

Under the allowlist policy this is safe because a non-allowlisted key is
rejected before any of it runs. Under the signature policy it is safe
because none of it runs until probation ends — and the decision is
**resolved again** at that point, against the table as it stands then, since
a round trip has passed and the entry may have appeared, been replaced or
ended in the meantime. The msg2 already sent carries the *earlier*
resolution's `resumed` flag; §2.2 says what a client should make of that.

### 4.2 How long a session lives

| Constant | Value | Where | Meaning |
|---|---|---|---|
| `MAX_SESSIONS_PER_OWNER` | 16 | `session_manager.rs` | backends (live + retained) one authenticated account may hold |
| `MAX_SESSIONS_TOTAL` | 128 | `session_manager.rs` | backends (live + retained) the daemon holds across every account |
| `RETAIN_AFTER_DEATH` | 3600 s | `session_manager.rs` | how long a backend outlives an unexpected death |
| `GC_INTERVAL` | 60 s | `session_manager.rs` | how often expired retained entries are reaped; passes stay at least this far apart, also after a stall |
| `SERVER_DEATH_AFTER` | 24 h | `conn.rs` | how long a silent session stays routable |
| `CLIENT_DEATH_AFTER` | 45 s | `conn.rs` | when a client gives up (default) |
| `ACTIVE_WINDOW` | 5 s | `session_manager.rs` | idle time within which a session counts toward the daemon's active-session count |

`SERVER_DEATH_AFTER` and `RETAIN_AFTER_DEATH` are not alternatives, and
they do not run at the same time: a silent session stays routable for the
full `SERVER_DEATH_AFTER` first, and only once that connection actually
dies does the backend become `Retained` and start counting down
`RETAIN_AFTER_DEATH` on top. A session that goes silent and never comes
back is gone `SERVER_DEATH_AFTER` + `RETAIN_AFTER_DEATH` after its last
packet — about a day, not the one hour `RETAIN_AFTER_DEATH` alone might
suggest.

`ACTIVE_WINDOW` is not a protocol timer. Its own doc, and the `is_active`
predicate beside it, say what it is for: version reconciliation and the
daemon's `STATUS` reply, which need to know how many sessions are genuinely
in use. A live client PINGs every 1.5 s, so an idle-but-attached one still
counts; a backgrounded or roaming one does not.

Two different things end a session, and they end it differently:

- a **graceful close** — a `Close` frame received, which the client sends on
  a deliberate disconnect — tears the backend down at once and removes the
  entry;
- an **unexpected death** — the liveness timer expiring with no `Close` —
  marks the entry `Retained { since }`, parks its datagram sender, and
  leaves the backend running. A later warm handshake with the same token
  revives it. Past `RETAIN_AFTER_DEATH` the GC drops it, which drops the
  channels the parked bridge is waiting on, which ends the backend. A GC
  pass that finds a handshake naming the entry's token in probation spares
  the entry once, until the next pass: that is a device coming back just
  as its time runs out, whose proof may already be with the verifier, and
  ending its login now would strand the session that proof is about to
  bind. Once, and no more, so replaying a token's handshake cannot keep a
  dead session alive. Once is a whole `GC_INTERVAL` even after the router
  has stalled: missed GC ticks are delayed, not fired back to back.

The client driver exposes both: `close()` sends the frame, `detach()` ends
the loop without sending anything, so the server sees plain silence and
retains (`driver_std.rs`).

Every `BackendEntry` carries an `owner` — the `uid` off the `Principal` that
authenticated the connection which created it (§3.2.1) — and admitting a new
backend (`admit_new_backend`) checks two caps against it, not one: this
account's own count against `MAX_SESSIONS_PER_OWNER`, and the daemon's
total against `MAX_SESSIONS_TOTAL`. Under both, admission is free. At its
own cap, the caller displaces only its **own** oldest `Retained` entry —
never another account's — and is rejected outright only once every one of
its own backends is `Live`. Under its own cap but blocked by the total
ceiling, the oldest `Retained` entry of *any* account is evicted instead.
Either way, an entry whose token a handshake in probation names is evicted
only if no other candidate is left, for the reason the GC spares one. And
either way "rejected" means no msg2 is sent, and every eviction and
rejection is logged; there is no silent cap. The same `owner` field is what
stops an authenticated caller from taking over another account's session: a
`WarmReattach` or a `ColdReplace` against an existing token (§4.1) is
refused (`refuse_foreign_owner`) unless the caller's own `uid` matches the
token's owner.

### 4.3 A warm return, from the client's side

`CLIENT_DEATH_AFTER` is a product decision, not a transport one, and
`set_death_after` overrides it. The console client keeps the default (45 s):
a dead link is the cue to walk its address ladder again in the background
and return to the same
session with the token it already holds (`cli/src/main.rs`,
`crates/connect/src/reconnect.rs`). A link that does not come back within
the death timer would not come back on its own later either -- the
transport has already ridden out whatever it could -- so waiting longer
would only delay the repair.

For a later run of `qsh` to return to the shell an earlier one left behind,
the token has to survive the process. `cli/src/sessions.rs` keeps it in
`~/.config/qsh/sessions` (or `$XDG_CONFIG_HOME/qsh/sessions`) as numbered
slots per effective login, exact first configured host text, and QSH port
(`MAX_SLOTS` = 16 per tuple, directory `0700`, files `0600`). There is no DNS
resolution, case normalization, or alias merging in this local key. A run takes
the lowest slot no live process holds, where "holds" is an exclusive `flock` —
released by the kernel however the process dies, so there is no stale lock and
no pid file. Two terminals using the same tuple get different tokens; different
logins have independent tokens and locks, each starting at slot zero.

Filenames are `v2-<lowercase SHA-256 hex>-<slot>`. The hash input is
`b"qsh/session-slot/v2\0"`, followed by the login's UTF-8 byte length as a
big-endian `u64` and its bytes, the host's UTF-8 byte length as a big-endian
`u64` and its bytes, and the QSH port as a big-endian `u16`. The decimal slot
number is appended separately. Framing prevents ambiguous tuple concatenation,
and hashing gives bounded filenames without path characters or sanitizer
collisions. This is a local storage format, independent of the wire protocol.

Legacy host-only records remain untouched and are never automatically imported
or claimed because they have no trustworthy login attribution. The new client
therefore cannot automatically resume a detached session through an old record;
it creates a fresh login-scoped record without terminating that server session.

The console client always announces `Warm` (`cli/src/connect.rs`): asking to
resume costs nothing when there is nothing to resume, whereas asking cold
would *replace* a session that is still there — precisely the one it came
back for.

---

## 5. Roaming

`Connection::on_transport` in `conn.rs`. A session is not identified by an
address pair, so changing address is not an event the protocol has to
negotiate — it is something the server notices and follows.

A datagram arriving from an address that is not the current peer moves the
session only if **all** of these hold:

1. the header's `session_id` matches this connection's;
2. the AEAD decrypts — with this session's keys, this counter as the nonce
   and the associated data of §1.1;
3. the counter would become a **new maximum** (`is_new_max`, captured before
   `accept` mutates the window);
4. the counter is not a replay (`ReplayWindow::accept`);
5. the frames inside are not **probing-only**. A datagram whose frames are
   all `PathProbe` / `PathProbeAck` never moves the session, however
   authentic it is — otherwise checking a backup road would drag the live
   traffic onto it. QUIC draws the same line between probing and non-probing
   frames. Note the exact test, the `probing_only` binding in
   `on_transport`: `!frames.is_empty() && all-probing`, so a datagram that
   decodes to **no** frames at all — an empty payload, or one whose first
   byte is an unknown frame type — is *not* probing-only and may move the
   session;
6. the role is `Server`;
7. the source differs from the current peer.

Then, and only then: `peer = src`, a `rehomes` counter increments, and an
`Event::Rehomed` is emitted. Keys, stream buffers, offsets and delivery
state are not bound to an address and do not change. What the sender knew
about the road does: the congestion window starts afresh, its base delay
and the send times of what is in flight are forgotten, and that data goes
out again under the fresh window (§7) -- as on the client when it moves.
A new port on the same address restarts too. Seen from the server, the
usual one is the client's own new socket (a network change, a wake from
sleep), which closes the old one: what was sent to the old port is lost in
one burst, and resending the flight repairs it at once where NewReno would
take a round trip per segment. A NAT that remaps while the old mapping
still delivers pays one slow start.

Inside `on_transport`, the block that assigns `self.peer` sits **above** the
`PathDown` → `Live` transition and the resync that follows it, and its own
comment says the order is deliberate: a long absence is exactly when a phone
is likely to have roamed while asleep, so the resync's `Reset` must be
addressed to where the peer is now, not to the stale pre-absence address.

Point 3 is what makes a late packet from the dead address harmless: it is
fresh-in-window, so it still delivers its data and its ACK, but it does not
advance the maximum and therefore cannot roll the peer back. Point 6 is
deliberate asymmetry — following the peer's source address is the *server's*
behaviour. A client roams on purpose, through the path table (§6); if it
also followed source addresses, one packet arriving over a road it had just
left would undo the move it had just made.

### 5.1 Liveness

Two clocks, and they answer different questions:

- `last_recv_auth` — the last authenticated packet of **any** content,
  probe answers included. "Is the peer alive at all?"
- `last_recv_ordinary` — the last authenticated packet carrying at least one
  non-probing frame. "Is the road **in use** carrying traffic?"

```
                              PING every 1.5 s (PING_INTERVAL)
                                        |
                                        v
     Connecting  ---- handshake ---->  Live
                                        |    ^
       3 s with no ordinary traffic     |    |  an ordinary (non-probing)
                  (PATH_DOWN_AFTER)     |    |  frame arrives
                                        v    |
                                     PathDown
                                        |         while PathDown, once 60 s
                                        |         have passed since the last
                                        |         authenticated packet of any
                                        |         kind (PING_BACKOFF_AFTER),
                                        |         the PING rate drops to 15 s
       the death timer expires,         |         (PING_INTERVAL_DOWN)
       or a Close frame arrives         |
       (from any state)                 v
                                     Closed
```

`Connection::ping_interval` measures that backoff from `last_recv_auth`, not
from when the path went down — so a peer that answers probes but carries
nothing keeps the lively PING rate, which is the right answer: something is
still listening.

The death timer counts from `last_recv_auth` on a server and from
`last_recv_ordinary` on a client, because they ask different questions: a
client that is plainly alive on *some* road must never have its session
killed, whereas a client whose road answers probes but carries nothing has a
useless session and should give up so its owner can start over.

PINGs are scheduled by the clock, not by silence: each one `PING_INTERVAL`
after the last, and the first one `PING_INTERVAL` after the handshake. Traffic
does not push them back, so a server streaming output from the start of the
session (a clock in tmux, `htop` after a reconnect) still gets PINGed, the
round trip is measured, and the unanswered-PING evidence §6 relies on exists.

The round trip is kept as a measurement or as nothing -- never as a zero
that means both. A client takes its first measurement from the handshake:
the time from sending msg1 to reading msg2, unless msg1 had to be
retransmitted or sent again behind a cookie (§2.4) -- Karn's rule: a reply to
a msg1 that went out twice cannot say which copy it answers. It includes the
server's work on msg1, but msg1 and msg2 cross an empty queue: a bulk write
right after the handshake (such as a daemon update) meets a far longer round
trip on a slow uplink. Every `PONG` replaces it. A server takes none from
the handshake: after msg2 the client may say nothing for a while. This round
trip -- the latest `PONG`, or the seed -- is what `Stats::rtt_ms` shows and
what road liveness reads.

The retransmit timer keeps its own estimate (RFC 6298): SRTT and RTTVAR,
gains 1/8 and 1/4, fed by every `PONG` and by every data segment acknowledged
without having been retransmitted (Karn's rule): the ACK that first covers a
segment times it from its first send, unless that ACK also covers a segment
that went out more than once -- after a hole is filled, the cumulative ACK
jumps over segments that arrived long before. The ACK's own delay on the
peer is inside the sample; that errs long, the safe side. Samples on every
acknowledged segment make the timeout follow the queue a bulk write builds
within one round trip. The retransmit timeout is then
`SRTT + max(4 * RTTVAR, SRTT / 4)` clamped to [200 ms, 15 s]; the `SRTT / 4`
margin keeps it clear of a steady queue, where per-segment samples drive
RTTVAR towards zero. The 15 s ceiling (RFC 6298 allows 60 s) is above road
liveness's 3 s on purpose: a 256 KiB window stands 4 s deep in a 64 KB/s
uplink's queue. Before any sample it is `2 * seed` clamped to [500 ms,
3000 ms] -- the seed may raise it above `DEFAULT_RTO` but never lower it --
and `DEFAULT_RTO` = 500 ms with nothing measured at all; a sub-millisecond
round trip (loopback, a fast LAN) gives the 200 ms floor. Each expiry --
a stream's oldest unacknowledged segment going out again -- doubles the
timeout (RFC 6298 §5.5, at most six times, never past 15 s) until a new
sample resets it, or until a packet ends `PathDown`: an outage is not a
queue being overfilled.

A freeze of the thread (Doze), a rebind and a move onto another road make
the data in flight untimeable, as they make the outstanding PINGs forgotten,
and drop the back-off: an ACK that waited through a freeze in the socket
would otherwise be one sample the length of the freeze. A move also forgets
the estimate -- it describes the road left -- and until the PING forced down
the new road is answered, or an ACK times something sent after the move,
the timeout is the liveness value of the latest `PONG` (below).

The estimate falls as slowly as RFC 6298 lets it: after a bulk transfer
over a deep queue (SRTT around 4 s at 64 KB/s) an idle session gets one
sample per `PONG`, and the timeout stays above 1 s for about 30 s. A loss in
that time is repaired at the old timeout; TCP behaves the same.

What this does not fix: a bottleneck queue smaller than the 256 KiB window.
Its tail drops are real losses, repaired by timeout alone (there is no
selective acknowledgement), and every resend round refills the same queue.
The transfer degrades rather than stalls -- 64 KB/s over a 64 KiB queue
crawls at about 860 s for 8 MiB -- until a congestion response or a
path-sized window (slice 2 of the transport-defects work).

Road liveness does not read that estimate. Its allowance is `2 * rtt` of
the round trip above, clamped to [200 ms, 3000 ms] (to [500 ms, 3000 ms] for
the seed), `DEFAULT_RTO` with nothing measured; it sets the move dwell and
the unanswered-PING rule. A PING counts as unanswered once an older
outstanding one is past both the PING interval and that allowance -- or,
while nothing is measured, past both
the interval and the 3 s ceiling, so the first PINGs on a road slower than
the interval are not called unanswered while their answers are on the way.
`Stats::rtt_ms` shows 0 for nothing measured, otherwise the measurement in
whole milliseconds, rounded, at least 1.

A frozen thread is not a dead link. If `recv` blocks far longer than the read
timeout asked for — `FREEZE_RESUME_AFTER` = 5 s in `driver_std.rs` — the
driver treats the wake as a rebind: a fresh socket on the current network,
both liveness clocks restarted at now, and a forced PING. The still-alive
server session then migrates to the new address over UDP instead of the
client slowly reconnecting.

### 5.2 A long absence

Output cannot be hoarded forever. While the path is down and
`RESYNC_AFTER` = 10 s have passed with no ordinary traffic, the server marks
its **bulk-output** streams desynced: their backlog is dropped and further
writes to them are discarded. On the client's return, each desynced stream
arms a reliable `Reset` at the new offset and the backend is told to repaint
the current screen — so the client gets the screen as it is now, not a
replay of the whole gap. `RESYNC_AFTER` sits well above `PATH_DOWN_AFTER`
so short blips and ordinary roaming still replay seamlessly.

Which streams are bulk output is *declared* by the session layer through
`set_stream_resyncable`, not inferred from the stream number: a backlog may
be dropped exactly when the channel that owns it has a screen model to
redraw from, and the transport has never heard of screens. A stream nobody
declared falls back to the old single-product rule, where stream 0 is the
bulk output. This matters: `channel.rs`'s `CONTROL_STREAM` is deliberately
**not** 0, because its records are one-shot and order-critical and a repaint
cannot regenerate a lost one.

---

## 6. Multipath

`paths.rs`. One session, several roads to the same peer — a LAN address, a
public one, one through a VPN. Moving between them costs an assignment, not
a reconnect. The module opens no sockets and sends nothing: it is asked what
should happen at an instant and answers with probes to send and a road to
prefer, which is what makes the tricky part testable without a network.

This section calls any one of a session's addresses a road — the one in
use as much as a spare one waiting to be tried — which is `paths.rs`'s own
name for it. The README and `qsh --help` only have a name for the spares,
and call those backups.

Only a **client** has roads. `Connection::on_timeout` runs the probe and
move logic under `matches!(self.role, Role::Client)`; a server does not know
what other addresses reach it.

A road starts `Unverified` and moves on what its probes do:

```
  Unverified  --- its probe is answered ------------->  Verified
  Unverified  --- 3 s silent (PROBE_TIMEOUT) -------->  Dead
  Verified    --- 3 s silent (PROBE_TIMEOUT) -------->  Dead
  Dead        --- a later probe is answered --------->  Verified
```

| Constant | Value | Meaning |
|---|---|---|
| `MAX_PATHS` | 8 | roads one session may keep |
| `PROBE_IDLE` | 30 s | probe interval while the live road is healthy |
| `PROBE_URGENT` | 1 s | probe interval once it looks doubtful |
| `PROBE_TIMEOUT` | 3 s | silence after which a road is `Dead` |
| `MAX_IN_FLIGHT` | 4 | unanswered probes per road (this is `paths.rs`'s own constant, unrelated to the same name in `reliability.rs`) |
| `FAILURE_PENALTY_WINDOW` | 60 s | how long a failure still weighs on a road |
| `FAILURE_PENALTY` | 10 s | how much it weighs |
| `UNVERIFIED_COST` | 60 s | assumed cost of a road that never answered |
| `DEAD_COST` | 3600 s | assumed cost of a road that failed its last probe |

Probes are `PathProbe` / `PathProbeAck` frames (§1.4) carrying a token. An
answer is attributed **by its token, not by the address it came from**: only
the real peer can produce an authentic answer carrying it, and a host can —
on plain Linux loopback, routinely does — reply from a different local
address than the one the probe reached it on.

Timing out is measured from `unanswered_since`, the moment a road went
quiet, not from the last probe sent. Under the urgent schedule a new probe
joins the others every second, so an expiry clock restarted by each of them
would never reach three seconds and a silent road would stay `Verified`
forever — exactly the case the urgent schedule exists for.

Round trip is smoothed as an EWMA, `0.8 * previous + 0.2 * new`.

**Ranking** is `score`, lower is better: a verified road costs its EWMA (or
1000 ms if it somehow has none), an unverified one `UNVERIFIED_COST`, a dead
one `DEAD_COST`; a road that failed within `FAILURE_PENALTY_WINDOW` pays
`FAILURE_PENALTY` on top of whatever its base cost was, so a flapping road
is not chosen, failed and chosen again. Neither stand-in is infinite: the
road you are on may be the only one there is.

**Moving** happens in `Connection::on_timeout` and needs three things at
once: the dwell since the last move has passed; the best road other than the
current one is `Verified`; and the road in use counts as down, which is
either of two conditions -- the state is `PathDown` (no ordinary frame for
`PATH_DOWN_AFTER`), or the road in use failed its own check (went `Dead`)
while its PINGs go unanswered, the two overlapping in time. The second
condition exists because the server keeps answering over the road just left
until an ordinary packet reaches it down the new one (`on_transport`'s
migration): while the server still has something to send back, ordinary
traffic never goes quiet and `PathDown` never fires on its own, so a failed
check on the road in use is paired with its own unanswered PINGs to catch
that case too. Neither one declares the link down alone -- a failed check
alone is one lost datagram, an unanswered PING alone is a slow round trip or
another lost datagram -- and neither do such losses that merely line up: the
PINGs must have been found unanswered no later than the road's latest
failed check was SENT (`PathTable::failed_at` is that send time, the start
of the silent run that expired), so that the check went down a road already
known to be dropping PINGs, failed too, and the PINGs are still unanswered.
Anchored on the check's expiry instead, the rule would pair losses up to
`PROBE_TIMEOUT` apart -- a PING and a check lost together, then another
PING -- which on a road with any round trip at all is three independent
losses. A single loss
does not linger either: a road in use that reads `Dead` makes the checks
urgent, so it is checked again within `PROBE_URGENT` and heals one round
trip later; a road that is really dead keeps failing those checks, and each
new failure overlaps the PINGs going unanswered. A PING counts as unanswered
once a newer one is minted while it is older than both the interval in force
and the retransmit timeout (`rto`, twice the measured round trip); up to
four outstanding PINGs are remembered and a PONG for any of them counts, so
a road slower than `PING_INTERVAL` is measured and, while its round trip
stays under the 3 s cap on `rto`, not read as failing.
Every automatic move forgets the PINGs sent down the road left -- their fate
says nothing about the new one -- and forces a PING down the new road on the
same tick, as a move by hand does: an ordinary packet down it clears
`PathDown` after one round trip and makes the server follow, where waiting
for the scheduled PING would outlast the dwell and bounce the client back
onto the road it just left. The dwell is
`max(2 * rto, PROBE_URGENT)` — `PathDown` clears only when an ordinary frame
arrives, and none can arrive before a round trip on the road just moved to,
so without it the next tick would be handed back the road just left, still
`Verified` because its own probe has not timed out yet, and the client would
flap.

**Moving by hand.** A client's owner can move the session onto one of its
roads itself: `Connection::use_road(addr, now)`, reached through
`StdClient::use_road`. It is refused unless this is a client with a session
(`NoSession`), `addr` is one of the roads handed to `set_paths`
(`UnknownRoad`), and the road is `Verified` (`NotAnswering`) -- by hand one
cannot go anywhere automatic moving would not; the road already in use is
accepted and changes nothing. A move is the same assignment as an automatic
one, plus two things: the dwell starts, so a tick during `PathDown` does not
overrule the choice with its own, and -- as at an automatic move -- the
PINGs sent down the road left are forgotten and a PING is forced on the next
tick, so the server follows after one packet (§5) instead of up to
`PING_INTERVAL` later. The liveness clocks are not restarted, unlike a rebind: the chosen
road has to prove it carries traffic. One that does not is left by automatic
moving as usual, on either of its two triggers above: it goes `PathDown`
after `PATH_DOWN_AFTER`, or -- when the server keeps talking over the road
left, so nothing about the traffic itself ever goes quiet -- it fails its
own check while the PINGs down it go unanswered, the two overlapping; either
way automatic moving
may then move the session again, possibly back onto the road left. Nothing
is pinned. Automatic moving only ever leaves a road that went quiet or went
dead under its own PINGs, so a road chosen by hand keeps the session for as
long as it carries traffic, however much faster another one is -- one lost
check does not count -- and nothing brings the session back to it once it
has been left. The server cannot tell a move by hand from roaming. The
console client asks for one from its connection-state window (`Ctrl-] s`,
then `Enter` on a spare; `use_road` in `cli/src/main.rs`).

Probes go urgent for exactly three reasons: the road in use is already
`PathDown`, the road in use failed its own last check (reads `Dead`), or a
liveness PING went unanswered (as defined above). Not
merely "a PING is in flight" — that is the ordinary state of a healthy link
for one round trip out of every interval.

On the console client, extra addresses on the command line *are* the request
for this; there is no flag (`cli/src/args.rs`). The address in use is
included in the list handed to `set_paths`, or there would be nothing to
come back to when it revives, and a name that will not resolve is dropped
with a line in the log rather than failing a connection that works.

---

## 7. Reliability

`reliability.rs`. UDP delivers datagrams; the protocol needs an ordered byte
stream. Each stream number has an independent sender and receiver pair
(`StreamState` in `conn.rs`), so ordering is guaranteed **within** a stream
and nothing is promised between streams.

**Sender.** Unacknowledged bytes live in one ring buffer starting at
`base_offset`: an `ACK` drops bytes from its head without moving the rest, so
what an acknowledgement costs does not depend on how much is queued behind it.
A ring that a burst grew past 1 MiB — past what any send gate lets through
(§8) — gives the room back as it drains: once it is down to a quarter full,
the bytes left move into a ring twice their size, never smaller than 1 MiB.
The bytes acknowledged since the ring was that big pay for the move.
A flush (`Connection::flush_senders`) puts out, in this order:

1. every still-armed `Reset` — immediately the first time, then only after
   `rto` has elapsed, so a burst of writes within one round trip does not
   produce a duplicate-Reset storm;
2. the **interactive** streams (keystrokes, terminal output, control records:
   everything nobody declared otherwise), round-robin, up to 4 segments per
   stream per turn — lost segments first, then new bytes — for as many turns
   as there is something to send;
3. the **bulk** streams (`StreamClass::Bulk`: the client's daemon image),
   the same way, but at most 32 segments per flush — 32 datagrams, since
   full segments never share one. What is left is due at once: the driver
   takes its commands — keystrokes — first and comes back.

**Acknowledgements.** An `ACK` does not go out for every `DATA` (spec
§4.11). What a receiver owes — one `ACK` per stream, the latest point, and
one `CREDIT` per stream, the newest limit — rides the next datagram this
side sends anyway (`DATA`, `PING`, `PONG`, `Reset`, `Close`); what nothing
carries goes alone `ACK_DELAY` = 20 ms after the first of it was owed. That
is below the 200 ms retransmit floor used before adaptive timeout tuning. It goes at once after
`ACK_EVERY` = 4 `DATA` frames that extended an unbroken stream; for a `DATA`
that did not — a repeat of what was delivered (the last `ACK` may be lost),
one past a hole, one that fills a hole (fast retransmit and recovery count
on these, RFC 5681 §4.2); for a `Reset`; and for room given to a sender
that may be stopped at its limit. A `PONG` goes the moment its `PING` is
read — it times a round trip — and takes what waits with it. The deadline
is one `Connection::next_timeout` reports and `on_timeout` serves; a
daemon's probation, which stops pumping its connection while a proof is
verified, sends what it owes first (`Connection::answer_now`). A peer may
acknowledge every `DATA` at once; this side counts an `ACK` for at most
`ACK_EVERY` segments in the window's growth, so a single-segment `ACK`
still counts only that segment.

What it costs and saves. A round trip timed by an `ACK` includes up to
20 ms of the receiver's wait: the safe side for a retransmit timer, and
well under the 50 ms the base delay is judged with (a `PONG` is never
held, and the base is a minimum). A flight that ends in a group of fewer
than four segments waits those 20 ms for its last `ACK`, once a round
trip — every round while the window is under the road's bandwidth-delay
product: right after a timeout, and all along on a lossy road. In the
simulator (8 MiB one way, 20 ms each way, 10 MB/s) a receiver sends a
quarter as many answer datagrams as it gets `DATA` datagrams on a clean
road (0.25) and two fifths at 1 % loss (0.41), against one each before; on
a lossy upload road (1 MB/s, 50 ms each way, 0.5 % loss, 8 MiB, 500 seeds)
the transfer takes 47.6 s against 45.4 s. Ending each flight the window
cut short with a `PING` — answered at once, the held `ACK` riding its
`PONG` — gave that time back but drew 0.71 answers per `DATA` at 1 % loss,
and one such `PING` at a time did not give it back; this build takes the
5 % on such roads for the answers saved everywhere. A `PING` that shares a
datagram with data times that datagram's time on the line too, as an `ACK`
of it would — on a slow uplink one segment's, 130 ms at 64 kbit/s. It
seldom does: a `PING` goes when its timer fires, and data then usually
waits for the window (at 64 kbit/s none of the 79 `PING`s of a minute of
typing and of a minute of bulk upload shared one), and the base delay does
not take such a sample.

**Congestion window.** On top of each stream's `MAX_IN_FLIGHT`, the whole
connection keeps at most a congestion window of DATA in flight (RFC 5681):
10 segments to begin with (RFC 6928), one more per acknowledged segment in
slow start, about one per window past the threshold (an ACK counting for at
most `ACK_EVERY` = 4 segments in either phase, RFC 3465's L sized to what a
delayed ACK covers), and only while the window — or the bulk budget of one
flush — was what held the data back, or the interactive class went past the
window on its allowance (a terminal session that a timeout left at one
segment writes past it without ever being stopped, and would not grow back
otherwise). That verdict is the last flush's that put data out: a flush
with nothing to send — `on_timeout` flushes at every deadline, the delayed
`ACK`'s among them — leaves it, since what is in flight went out under the
verdict of the flush that sent it. When the retransmit timer expires the
threshold becomes half of what was in flight, counting the flight as at least
the initial window (so at least 5 segments: one lost keystroke on a quiet
session does not pin it low), the window one segment, and only the oldest
segment goes out again at once; the rest follow as the acknowledgements open
the window. Until what was in flight at the timeout is acknowledged, an ACK
counts for one segment of slow start, not four (RFC 3465 §2.3): the ACK that
answers the resend covers everything the receiver held behind the hole, and
counted as four it would let five segments out on a window of one. A timeout
can be a mistake: an `ACK` slower than the timer
allowed, held by a queue that grew on the way back while the timer was still
measured on an idle road. So the first `ACK` that moves a timed-out stream
decides, once (after RFC 5682's F-RTO and the Eifel algorithm, without their
timestamps): sooner than the road's base delay after the resend -- by more
than `HOST_SLACK`, see below -- it cannot answer the resend and answers the
original. Then the window, its threshold, the learned duplicate threshold
and the timer's back-off go back to what the timeout found, and what it took
for lost is in flight after all -- not sent again, and timed afresh
(ordinary flushes in between do not change that); a probe the timeout ended
comes back too. A timeout that ends a recovery is not undone, nor one after
which a recovery began: that is a newer cut. The limits are the heuristic's:
an `ACK` that the queue on the way back holds for longer than the base after
the resend reads as an answer to it, and the timeout stands -- with a single
segment in flight nothing without timestamps tells the two apart. And the
timeout's hold on fast retransmit stays after an undo: a real loss right
behind the late segment, its duplicates held, is found only by the next
timeout. Giving the hold back cost more than it saved -- on a road that
holds 1 % of the datagrams back by 150 ms, 36.4 s against 26.9 s for 8 MiB.
The interactive class may have two segments more in flight than the window,
and always two segments of its own, however far the bulk flight stands above
the window after a cut: a keystroke does not wait for the bulk data to
drain. A move onto another road, a rebind and a wake from sleep start the
window afresh -- the client's when it moves, rebinds or wakes, the server's
when it follows its client to a new address or port -- and what was in
flight then is resent under the fresh window rather than taken for a
timeout. This requires no extra frame: the peer sees a sender that sends
less at a time.

One more signal is not in NewReno: a round-trip sample (a `PONG`, or an `ACK`
timed by Karn's rule) more than 500 ms (`QUEUE_DELAY_CAP`) above the road's
base delay is taken as congestion — the same halving as a fast retransmit,
nothing resent — at most once per round trip and not within one of a
loss's cut, not during a recovery, and never raising the window. Only while
the sender had data waiting within that round trip — held by the window,
the bulk budget of a flush or a stream's own 256 KiB: an
application-limited sender, a terminal session, is not what stands in the
queues its round trips cross, and cutting its window would only slow its
next burst. A bottleneck buffer as deep as the window loses nothing, and
without this the window would stand seconds deep in a slow uplink, with the
`PING`s and road checks behind it. The base delay is the smallest round trip
of the last ten minutes, kept as one minimum per minute (LEDBAT's
`BASE_HISTORY`, RFC 6817): long enough that a transfer's own standing queue
does not become "the road", short enough that a road that got slower
without a move is measured as it is within ten minutes. A move, a rebind
and a wake forget it with the window.

A transfer that never pauses would still lift the base in the end: behind a
buffer deeper than the road needs the halving leaves a queue standing (some
200 ms on a 100 ms road), and a window the stream's own 256 KiB holds below
the cap leaves one that nothing cuts. Measured without a remedy, the base
rose each time its minute left the history, and the queue the delay signal
keeps crept from 0.5 s towards 0.9 s over half an hour. So once no round
trip has come within 50 ms of the base for nine minutes — timed from the
start of the minute that round trip fell in, so the probe always comes a
whole minute before the base could leave the history — the window probes
the road (after BBR's ProbeRTT and LEDBAT++'s periodic slowdown): it drops
to two segments and holds there -- the ACKs of what drains grow nothing --
until the flight has fallen to what the probe lets out and a round trip of
something sent after that is measured: the road without our queue, whatever
it measures. A `PING` leads what goes out at that moment: the `ACK` of two
segments may wait `ACK_DELAY` at the receiver, a `PONG` never does, and the
`ACK` of what went out with the `PING` rides its `PONG` — otherwise the base
would read up to 20 ms long, and the undo rules above would take genuine
answers to a repair for early ones. Then a slow start climbs back to what the
road carries without the queue -- the rate when the probe began times the
round trip just measured, within half the initial window and the window it
left -- and congestion avoidance grows from there. Not the old window: its
excess was the queue just drained, and a slow start doubling past the road's
bandwidth-delay product sends at twice the road's rate in its last round
and sets off the delay signal a round trip later.

A probe starts only where our own flight can be holding the queue: the
sender had data waiting within the round trip, and more is in flight than
the probe would leave (its two segments and the interactive allowance).
Otherwise — an idle terminal session whose road got slower, one whose round
trips carry someone else's queue — that round trip already measures the
road as it is for us, and the due probe counts as done without touching the
window. No probe starts during a recovery or within a round trip of a cut (a
cut drains already); the delay signal is silent while one runs; a loss or a
timeout during it ends it, and it comes again once it may. A lossy road
seldom needs one: at 0.05-0.5 % loss its losses empty the queue often
enough that the base is seen. The interactive class keeps its own two
segments and control frames never wait for the window, so a keystroke typed
during a probe waits only for the queue already on the line. A probe costs
its minute under 1 % on a 100 ms road (at 32 KB/s and at 500 KB/s) and
9 % on an 800 ms road at 250 KB/s.

Three limits of a round-trip signal:

- **Someone else's queue.** Another flow's standing queue deeper than 500 ms
  puts every round trip of a sender with data waiting over the cap: the
  window stays near half the initial window (the interactive class two
  segments more, and its own two) until the base takes that queue in, at
  most ten minutes; qsh then competes as NewReno does. A road whose round
  trip itself grows by more than 500 ms without a move (a fall-back to an
  older radio) is held the same way for the same time.
- **The way back.** A round trip carries the queue on the way back as well
  as the one on the way out. The server's terminal output, application-limited,
  is not cut for the client's upload queue on its return path; its own bulk
  download during a client upload is. Measured, 32 KB/s up and 250 KB/s
  down behind 1 MiB queues: the download runs at 240 KB/s alone and at about
  30 KB/s while the client uploads -- its window held at 8-16 KiB by round
  trips that carry the upload's 0.55 s queue on the way back. Without the
  delay signal on either side it fell to 2-4 KB/s: the upload then stood
  8.5 s deep in front of the download's ACKs. Telling the two ways apart
  needs one-way delays, which the wire does not carry.
- **Very slow roads.** The probe's queue counts as gone once no more than
  its two segments and the interactive allowance are in flight, 4.4 KB. On
  a road whose bandwidth-delay product is smaller, what the probe measures
  includes the rest of those as queue: up to 34 ms at 32 KB/s on a 100 ms
  road, some 450 ms at 8 KB/s.

Three duplicate cumulative `ACK`s in a row (every `DATA` past a hole draws
one at once; the threshold may have learned a higher number, see below) resend
the oldest unacknowledged segment at once and halve the window: `ssthresh`
by the same rule as for a timeout, `cwnd = ssthresh` plus one segment for
each of the duplicates that set it off (3 unless the threshold is higher),
and one more for each later duplicate. A partial `ACK` resends the next hole
at once, and the `ACK` that covers everything in flight at the loss ends
the recovery with `cwnd = ssthresh` (RFC 6582, NewReno). There is no SACK:
holes are repaired one round trip apart. Every repair restarts the
retransmit timers of what is still in flight -- RFC 6582's
"Slow-but-Steady" variant, not the RFC's own step 4 ("Impatient", the first
partial `ACK` only): here a timeout resends everything due, much of it
already delivered, and a recovery with many holes would end in one.

A duplicate is an `ACK` whose `cum_ack` equals the sender's base exactly
while bytes past it are in flight; not one below the base (stale, ignored,
the run goes on) and not the one that answers an armed `Reset`. After a
retransmit timeout or a restart, copies of segments the peer may already
have are on their way, each drawing an `ACK` of the base: a stream starts
no recovery until an `ACK` passes everything it had sent by then (RFC 6582
§3.2 step 1). After a recovery the same hold runs to where the recovery
began (its `recover`), where its repairs end; data first sent during the
recovery is not held, and a full `ACK` already past that point holds
nothing.

A road that reorders sets off fast retransmits for segments that were only
late. The `ACK` of such a segment comes back sooner than the road's base
delay after the resend: most likely it does not answer the resend (the
heuristic of RFC 8985 §6.2). Sooner by more than `HOST_SLACK` = 2 ms: the
base is taken from round trips under load, and those carry the hosts' own
time -- a driver stamps a segment at the start of its pass and sends it at
the end, a peer answers a whole receive batch at once -- which the answer to
a lone resend does not. On loopback that answer came in 0.44-0.56 ms against
a base of 0.7-1.0 ms, and real losses read as spurious. On a road whose
base is within the slack none of the undo rules fires: plain NewReno and
the timer. Then the retransmit is taken for spurious and
undone (after RFC 4015, without timestamps): the window and threshold go
back to what they were before it, and the duplicate threshold rises to one
past the duplicates that came before the late segment, at most 64 (like
Linux's `tcp_reordering`). Every retransmit timeout puts it back at 3 -- the
reordering was overestimated, or the loss came in a flight too short for it
(our rule: Linux's `tcp_enter_loss` lowers it only in a narrower case) --
and a move, a rebind and a wake forget it, and the base delay, with the
window. Within a recovery, an `ACK` too early to answer the last repair
resends nothing. The heuristic can misjudge: a genuine repair answered
sooner than that (the road getting faster by more than the slack, the rare
low tail of its delay variation) is undone -- its halving skipped. Bounded
in time, not in count: until a round trip measured on the faster road
lowers the base -- a `PONG`, one every `PING_INTERVAL`, or an `ACK` timed by
Karn's rule -- every repair answered that early may be misread. After an
undone fast retransmit the `ACK`s of the data behind it are timed soon;
after an undone timeout the `ACK`s that follow cover resent segments or jump
a hole over them, Karn's rule times neither, and the next timeout may be
undone as well. And a base from before the road got slower leaves deeper
reordering undetected for up to ten minutes.

One recovery at a time for the whole connection, not one per stream:
another stream's third duplicate during it resends that stream's oldest
segment without a second cut, but that stream's partial `ACK`s resend
nothing and restart no timer -- its next hole waits for three more
duplicates of its own -- and no stream's window grows until the recovery
ends; a retransmit timeout, a restart or the stream's desync end it (a
desync as a full `ACK` would: `cwnd = ssthresh`).

**The hard cap.** A stream's tail — queued and not yet acknowledged — past
`SEND_HARD_CAP` = 4 MiB means a producer above ignores its send gate (§8).
On the daemon a stream with a screen model then takes the long-absence path
at once (backlog dropped, `Reset`, repaint); any other stream keeps its bytes
and the daemon logs it once per connection. A client never drops a stream:
it keeps the bytes and writes the same line to its standard error, once.

New bytes are cut at `MAX_SEGMENT_SIZE` = 1024, up to `MAX_IN_FLIGHT` =
256 KiB outstanding per stream. A timer's own frames go before any of this:
`on_timeout` puts the road checks and the PING out ahead of the data it
flushes. That order holds within one flush only: data an earlier flush put
out (a `send`, an `ACK`, the previous pass) may still fill the bottleneck
queue, and a PING waits behind it there — as long as the queue the
congestion window and the delay signal leave standing, near 500 ms.

The retransmit wake-up is per segment: `Connection::next_timeout` asks every
stream for `StreamSender::retransmit_deadline`, the oldest unacknowledged
segment's last send plus `rto` (and an armed `Reset`'s last send plus `rto`).
Sending anything else -- an `ACK`, a `PING` -- does not move it, so a side
busy acknowledging an inbound flow still retransmits on time.

**ACK clocking.** An `ACK` that moves a sender's base forward sends the next
bytes of that window in the same breath: the window refills when the
acknowledgement arrives, not on the next timer.

**Acknowledgement is cumulative**: `Ack { stream_id, cum_ack }` means every
byte below `cum_ack` arrived. `on_ack` clamps the value to what was actually
sent — an ACK for buffered-but-unsent bytes would otherwise cut them out of
the buffer so they never went out, a silent permanent loss — and never moves
the base backwards.

**Receiver.** Out-of-order segments are buffered in a `BTreeMap` keyed by
offset; a contiguous run from `next_offset` is delivered as soon as it
forms. Repeats and partial overlaps are handled without moving the point
backwards, and on a collision the longer chunk wins. What a receiver keeps
is bounded for every peer, honest or not (QSH-01): nothing at or past the
window its sender may use — 256 KiB past the cumulative point for a sender
without credits (`LEGACY_RECEIVE_WINDOW`, the window every such sender stays
in), the announced limit with credits (below) — is kept or acknowledged,
and a chunk inside it is kept only while what the stream holds costs no
more than one window of full segments, each chunk counted as its bytes plus
`CHUNK_COST` = 128. That is what a chunk's place in the map and the smallest
heap block of its bytes were measured to take at most, however a peer
orders its chunks (with glibc and musl), so one-byte chunks buy no more
memory than their cost says. What it leaves out is the allocator rounding
the bytes themselves up: with musl a window of full segments takes up to a
tenth more than its cost. All streams of a connection together hold at
most `UNDELIVERED_CAP` = 8 MiB of such cost, 64 KiB in probation (§3.3). A
chunk that does not fit is dropped unacknowledged, and its sender sends it
again; bytes in order are delivered whatever the buffer holds.

**Credits** (`stream-credit`). Each stream, in each direction, starts with
an implicit limit `STREAM_WINDOW` = 512 KiB past its first byte: a sender
puts out new bytes only below its limit (retransmits are neither checked
nor charged), and the receiver keeps nothing at or past it. The receiver
moves the limit on as its consumer takes bytes — `consumed +
STREAM_WINDOW` — and says so with `CREDIT { stream_id, limit }`; a limit
only grows, a lower one is stale and ignored. What counts as taken is up to
the owner: on delivery (`Consumption::OnDelivery`, when its callback
returns), or when it says so (`Consumption::Explicit` and
`Connection::on_consumed`: the daemon, §8, and the console `qsh` for its
channels — taken when the bytes reach the terminal, so a slow terminal
holds back only its channel, at most a window; against a daemon without
credits its driver waits once more than 1 MiB waits for the terminal);
what is consumed never passes what was delivered. A `CREDIT` goes out when
the limit grew by `CREDIT_UPDATE_STEP` = 128 KiB since the last one. The
sender may be stopped exactly when the data received reaches the oldest
limit it may still hold — a sender at its limit writes up to it exactly, its
last segment cut there, never short of it; smaller growth is not announced,
since a stopped sender has left the receiver at least `STREAM_WINDOW −
CREDIT_UPDATE_STEP` not yet taken. If that oldest limit is older than the
newest (a `CREDIT` lost on the way, or one held back by
`CREDIT_ANNOUNCED_MAX`), the newest is sent again one `rto` after it was
last sent — by an announcement, an explicit repeat, or a PONG copy,
whichever was last — or at once if that was already an `rto` or more ago;
three times in all, one `rto` apart. From the moment the sender may be
stopped, during those repeats and after them, a PONG may carry it too, until
data comes past the older limit: one copy per PONG at most, the streams that
may be stopped taking it in turn, and none for a stream whose newest limit
went out less than an `rto` before (§9.6 says why). An honest stop — one or
two streams — gets a copy with nearly every PONG; with `k` streams that may
be stopped, a sender whose announcement and repeats were all lost waits up
to `k · max(rto, PING_INTERVAL)` for its copy, since each stream's turn
comes at most once per its own `rto`. A sender stopped at the newest limit,
with a consumer that takes nothing, is told nothing: there is nothing new.
A receiver keeps at most `CREDIT_ANNOUNCED_MAX` = 16 limits a sender may
still hold per stream; while the list is full, further growth waits until
data passes the oldest. A `Reset` to `q` counts the bytes it skips as
taken and announces the room with its ACK. A sender that drops its backlog
takes `max(limit, q)` as its limit, and the receiver, unless data past `q`
has already arrived, puts `q` first among the limits the sender may hold:
the sender's limit is always one the receiver knows. The repaint goes out
at once when the dropped backlog fit under the old limit; when it did not,
it waits one round trip for the `CREDIT` on the `Reset`'s ACK. A `CREDIT`
is owed like an `ACK` (Acknowledgements, above): it rides the next datagram
out or goes alone within `ACK_DELAY`; room for a sender that may be stopped
goes at once, as does the room a `Reset` gives, and the repeats go on their
timer, packed with whatever else is due. With a peer that did not
agree `stream-credit` there are no limits, and a receiver keeps at most
`LEGACY_RECEIVE_WINDOW` past its point.

A consumer that stops therefore stops only its stream: the sender stands
at the limit with nothing in flight, so nothing is resent, and every other
stream, the PINGs and the road checks go on.

**Reset** is a reliable discontinuity, not a control message: the sender
re-arms it on every flush until it is acknowledged, so duplicates are the
norm. The receiver applies it only if it actually moves the point forward.
A stale or duplicate `Reset` that rewound would un-deliver bytes the sender
has already dropped from its own buffer, stalling the stream permanently.
The ACK goes out either way, because it is the ACK that clears the sender's
armed `Reset`. Only a server drops a tail and resyncs (its screen streams,
§5.2), so only a client takes a `Reset`: a server drops one from a client
whole — no point moved, nothing counted as taken, no limit, no `CREDIT`, no
ACK, not even a stream made for its number (§9.6). No client build sends
one; there is no armed `Reset` for an ACK to clear.

**Stream offsets.** The wire carries 32 bits of an offset (`u32` in `DATA`,
`ACK` and `RESET`); inside the process every offset is a 64-bit count of the
stream's bytes. With `offset-wrap` (§2.6) a field is read as the full offset
nearest where its reader stands — the sender's base for an `ACK`, the
receiver's cumulative point for `DATA` and `RESET` — whose low 32 bits it
holds (RFC 1982; QUIC expands its packet numbers the same way, RFC 9000
§A.3). That is unambiguous while everything of one stream in use at once
lies within 2³¹ bytes of it: at most 256 KiB is in flight, a receiver keeps
at most a window past its point (**Receiver**, above), and a `RESET` jumps
the point over the tails its sender dropped. The send gates and
`SEND_HARD_CAP` (4 MiB) keep each tail small, and even the tails of several
resyncs whose `RESET`s were lost one after another — a sender that drops
its tail again forgets the unacknowledged `RESET` and names its new head —
add up to far less than 2³¹. So a receiver takes a `RESET` however far
ahead a field can name; refusing one would stall the stream for good. The
only ceiling it keeps is the full offset 2⁶² (`FULL_OFFSET_MAX`, more than a
century of one stream at 1 GB/s): nothing past it, `DATA` or `RESET`, is
taken, so crafted frames cannot walk its point to the end of the 64-bit
count. A field exactly 2³¹ away reads as behind, and one that would name an
offset below zero is ignored. A stream simply goes on past 4 GiB, and a
fast recovery's point is a full offset too.

When a protocol-2 connection negotiates without `offset-wrap`, offsets do not
wrap. A
sender refuses to queue a byte past `OFFSET_LIMIT` = `u32::MAX` − 16 MiB:
the write is refused, the connection reports `Event::OffsetSpaceExhausted`
once for that stream, and its owner drops the connection without a `Close`
(`Connection::abandon`). The daemon parks the session and keeps its
processes either way. What happens next depends on who abandoned and which
client it is:

- The daemon abandons (its output stream reached the limit -- the likely
  case). The client is told nothing: it sits in `PathDown` until its death
  timer closes the connection. The console `qsh` reconnects warm at its
  45-second death timer, in the background, into the same session; the
  repaint after `ResumeReset` restores the screen.
- The client abandons (its own stream reached the limit). The console
  `qsh` reconnects warm at once.

That is one such break per 4 GiB of one stream over one connection, and
only without `offset-wrap`. A receiver in that mode drops a `DATA` frame
that ends past `u32::MAX` without delivering or acknowledging any of it.

**Congestion control** is of the simplest kind: one window per
connection, no pacing, no SACK — holes are repaired one round trip apart.
Anything faster is the file-transfer work's.

---

## 8. Channels

`channel.rs` and `channel_server.rs`. The transport carries several logical
channels over one session — a shell here, a `tmux -C` client there — the way
sshd does, and the transport itself knows nothing about what runs in them.

**Stream numbering** is the channel identity:

| Stream | Who defines it | What it carries |
|---|---|---|
| 0 | `shell_server.rs` (`STREAM_IO`) | the single-PTY product's shell I/O |
| 1 | `channel.rs` (`CONTROL_STREAM`) | session control records |
| 14 | `channel.rs` (`UPDATE_STREAM`) | a daemon image, after an accepted offer — never reaches a channel |
| 15 | `auth.rs` (`AUTH_STREAM`) | the client's proof — never reaches a backend |
| 16 … 255 | `channel.rs` (`FIRST_CHANNEL_STREAM`) | one channel's data, per stream |

Stream 0 and stream 1 belong to two different products, and they cannot meet
on one connection because their entry points are disjoint.
`shell_server::serve_shell` drives one PTY wired in at start-up (stream 0
for I/O, stream 1 for resize), and has exactly one production caller: the
diagnostic `transport-shell` subcommand, which drives a `Connection`
directly with no `SessionManager` at all (`run_transport_shell_command` in
`qshd/src/main.rs`). Everything that goes through a `SessionManager` —
`qshd serve` and `qshd transport-ensure`, so every real client, this console
one included — gets `ChannelSessionBackend` and therefore
`channel_server::run_channel_session` (`run_serve_command` in
`qshd/src/serve.rs`, `become_transport_daemon` in `qshd/src/main.rs`).

**Send gates.** Every channel has a gate on its stream that closes when what
the daemon holds for it — queued and not yet acknowledged, and what the
channel has handed to the session's bridge that the bridge has not taken
yet — reaches a high mark, and opens again at a low one. A channel with a
screen model (128 KiB / 32 KiB) never stops its process: while the gate is
closed its output only feeds the model and is dropped, whole `REC_DATA`
records at a time, before the transport — nothing on the wire changes and no
`Reset` is needed. The first chunk after the gate opens, or the bridge's
`Writable`, sends one repaint instead, then an `ECHO_ACK` with everything
consumed, whether or not it moved: the dropped output may have carried a
keystroke's echo. The echo ack tick skips a channel while its gate is
closed, and while its repaint is still pending after the gate opened. A
channel whose process ends while output it dropped is still unrepainted
sends its repaint before the channel goes. A channel without a model
(`tmux -C`: 512 KiB / 256 KiB) presses on its process instead: its reader
waits for the gate before it reads, and the process blocks writing to its
PTY, as behind a slow SSH. The control stream has no gate. In the required
channel-geometry profile, a parked bridge stops admitting output and retains
pending DATA charges, metadata permits and the previous connection's frozen
unacknowledged tail. It does not force gates open or discard NoScreen output.
Backpressure therefore remains effective while the client is gone. Reattachment
replaces the old connection tail while preserving pending ownership; ordered
bootstrap and retained output drain under the new connection's admission limits
as described below.

**Consumption.** The bridge's connection counts every stream explicitly, the
proof's excepted, and who says WHEN a stream's bytes count as taken is the
backend's own property, fixed before it runs
(`SessionBackend::consumption`): a backend that does not report
(`Consumption::OnDelivery`, the default) is counted the moment the bridge
hands its bytes over; one that reports
(`Consumption::Explicit`, `SessionIo::consumed`, from a blocking task
`SessionIo::consumption_reporter`) is counted only by its reports, so its
credit (§7) moves on when its bytes actually leave the daemon rather than
when they merely reach the bridge. In this build the only production
backend, the channel runner, is `Explicit`. A warm reattach brings a
connection whose streams start at zero while the backend may still hold
bytes THIS BRIDGE handed it off the old one and never reported: those are
owed to the old connection, and the first reports of each stream pay them
off before anything credits the new one; bytes the old connection merely
delivered but the bridge never handed to the backend (a datagram queued
into a connection itself replaced before its events were drained) are not
owed to anyone. A connection in probation counts explicitly too, so what a
client sends before its proof is taken when its backend takes it. The
channel runner reports: a control record once applied, a channel's input
once written to its process — and, once the process is gone, as its writer
drains the rest — and bytes for a stream that names no open channel at
once.

**The bridge does not wait for its backend.** What the backend's inbound
queue has no room for waits, in order, in the bridge, and goes as room opens;
meanwhile the bridge reads datagrams, answers PINGs and runs its timers. A
backend that stops reading its queue stops every inbound stream -- they share
the one queue -- but not the connection: its ACKs, PINGs, timers and output
go on. A channel's process that stops reading stops only its own stream: the
channel holds the bytes the process has not taken, and the stream's credit
(§7) stops the client there. What waits in the bridge is bounded per stream
per connection by its credit window and per session by `PENDING_CAP` =
8 MiB: a session has up to 256 streams, and every warm reattach brings a
connection whose streams start with a fresh window while the replaced one's
bytes still wait, so the windows alone do not bound the session. The same
goes for what a channel holds that its process has not taken: each warm
reattach while a process leaves its input unread can add up to one more
window on that stream, the replaced connection's bytes still queued in the
channel — bounded by what the client still has to send, and never past
`PENDING_CAP` for what waits in the bridge. Past `PENDING_CAP` the bridge waits
for its backend, as every build did. An honest client uses at most 10
streams -- 5 MiB of windows -- and never gets there. A client without credits
knows no limits, and the same cap is all that bounds it: an ordinary paste
never stops its bridge. Bytes are handed over when they enter the backend's
queue, not when they start to wait: a waiting byte is not counted as taken,
which is what keeps the wait inside the window. And they are counted for the
connection that delivered them: bytes a connection delivered that still wait
when a warm reattach replaces it are that connection's when they reach the
backend -- owed to it, like the rest of what the backend holds from it, if
the backend reports, and credited to nobody if it does not -- never the new
connection's. When a session ends gracefully, what still waits goes to the
backend, in order, before its queue closes.

**What a repaint restores.** A repaint is what the channel's screen model
(`TerminalCore::replay`, in `crates/terminal`) answers, and it restores not
only the screen but everything the output after it is read against, so
that output lands on the client as on the model: both screens (the primary
one too while the alternate one is shown, and its cursor), the cursor with
a pending wrap at the last column, the saved cursor, the pen, the scroll
region, origin mode, autowrap, insert mode and LNM, the character sets and
which one is active, the input modes (cursor keys, keypad, mouse levels and
encodings, focus, bracketed paste), cursor visibility and style, the tab
stops, the palette, the last printed character (what `CSI b` repeats), and
last the unfinished escape sequence or UTF-8 character the output stopped
in, so both parsers stand in the same place. It begins by ending a
synchronized update (`CSI ? 2026 l`), whose ESC also ends whatever sequence
the client was left inside. On the primary screen it rewrites the rows in
place — cursor addressing, no `ED 2`, nothing that scrolls — so the
client's scrollback gets no copy of its screen; soft-wrapped rows are
reached by wrapping, as the model reached them. Not restored: hyperlinks,
the window title, and the alternate screen's saved cursor while the primary
screen is shown.

**Only the client opens channels, and it picks the stream number.** Nothing
can collide, so no allocation protocol is needed. `MAX_CHANNELS` = 8 may be
open at once.

Records on `CONTROL_STREAM`, in the envelope of §1.5:

| Kind | Direction | Meaning |
|---|---|---|
| `0x10` `OPEN` | client | open a channel — see the layout below |
| `0x16` `RESIZE_REQUEST` | client | `stream(1) instance(u64) request_id(u64) cols(2) rows(2)` |
| `0x12` `CLOSE` | client | `stream(1)` |
| `0x13` `TERM` | client | the client emulator's terminal type, before the first `OPEN` |
| `0x14` `ABOUT_REQUEST` | client | "who are you" — empty body |
| `0x15` `UPDATE_OFFER` | client | `build(u64) checksum(32) size(u64) arch_len(1) arch` |
| `0x20` `OPENED` | server | `stream(1)` — it is running |
| `0x21` `REFUSED` | server | `stream(1)` + a human-readable reason |
| `0x22` `EXIT` | server | `stream(1) code(i32)` — the process ended |
| `0x28` `PROTOCOL_ERROR` | server | `code(u16)` |
| `0x29` `CHANNEL_SNAPSHOT` | server | one atomic active/draining lifecycle snapshot after warm attachment |
| `0x24` `ABOUT` | server | `build(u64) checksum(32) arch_len(1) arch protocol(1) mode(1)` |
| `0x25` `UPDATE_ANSWER` | server | a code; `Busy` adds `others(u32)` |
| `0x26` `UPDATE_RESULT` | server | a code; `Rejected` adds `reason_code(1)` and a UTF-8 detail, `Busy` adds `others(u32)` |
| `0x27` `RESTARTING` | server | the daemon is about to replace itself — empty body |

An `OPEN` request has this layout. Active snapshot entries reuse this
encoding after their nonzero `instance(u64)`:

```
  stream(1) | kind(1) | cols(2) | rows(2) | flags(1) | cmd_len(2) | command
              0=Shell                       bit 0 =
              1=Command                     screen
```

`CHANNEL_SNAPSHOT` contains `active_count(u8)`, the active entries,
`draining_count(u8)`, then draining entries. Each draining entry is exactly
15 bytes: `stream(1) instance(u64) kind(1) cols(2) rows(2) screen(1)`.
It retains immutable OPEN classification after the process has ended; it is
not a writable channel or an authoritative geometry update. Active entries
carry the runner's current OPEN request, including its command. Commands are
at most 4096 bytes; active count is at most 8 and active plus draining at most
240, the stream IDs 16–255. A stream appears only once across both lists.

`channel_snapshot.rs` preflights the entire payload without allocations,
checking counts, uniqueness, instance IDs, classification, command lengths,
geometry and exact exhaustion. Its maximum payload is
`2 + 8*(8 + 9 + 4096) + 232*15 = 36,386` bytes (36,391 framed), below the
64 KiB control-record cap. Retained arrays and commands are normalized to
validated lengths. Eight live channels does not bound ended channels to eight.

`REFUSED` is `stream(1)` followed by its UTF-8 reason; `EXIT` is
`stream(1) | code(i32 big-endian)`. Retired kinds `0x11` and `0x23` are
malformed known messages, not accepted legacy messages or skippable extensions.

`cols` or `rows` of 0 means "no pseudo-terminal". `take_open` rejects a
stream below `FIRST_CHANNEL_STREAM`, a `Shell` request with a non-empty
command, and a `cmd_len` above `MAX_COMMAND_LEN` = 4096 — the last one
before the length can become an allocation request. `TERM` is validated
against a terminfo-shaped alphabet and `MAX_TERM_LEN` = 64, so a newline or
a path separator can never reach an environment variable.

The update records are tail-extensible. In `ABOUT` only `build` is
required; each later field is either whole or absent together with every
field after it, and an absent field reads as its default (a zero checksum,
an empty architecture, protocol `0`, mode `0`). A field cut off half-way is
`Malformed`. Bytes after the last known field are a newer peer's and are
skipped. `mode` is `0` for a daemon a client installed and keeps up to date,
anything else for one a service manager or a package owns. Answer codes:
`0 Accept`, `1 UpToDate`, `2 DaemonNewer`, `3 Busy`, `4 Managed`,
`5 ArchMismatch`, `6 TooLarge`, `7 NotAllowed`, `8 InProgress`. Result codes:
`0 Restarting`, `1 Rejected`, `2 Busy`. `Rejected` carries a reason code,
then an English detail meant for a log: `0 other`, `1 size mismatch`,
`2 checksum mismatch`, `3 self-check failed`, `4 version not accepted`,
`5 disk error`, `6 exec failed`, `7 transfer stalled`, `8 control socket busy`
(the control socket could not be held still in time, §8.1; nothing was
replaced). An unknown code is kept as such
(`Unknown`), not treated as malformed. `arch` is lower-case letters, digits
and `_`, at most `MAX_ARCH_LEN` = 32 bytes. `PROTOCOL_VERSION` is `2`;
`qshd self-check` advertises `protocols:[2]`.

The `screen` flag is what the client *asks for*, not what it gets: the
server declares a channel's recoverability from the spawned channel's own
answer (whether it has a screen model), both at open and again after a warm
reattach. That declaration is what `set_stream_resyncable` carries into the
transport (§5.2).

`CHANNEL_SNAPSHOT` is the first control record on a warm attachment. The
runner and bridge combine active and draining owners into one atomic snapshot
and fence receive-side channel input until this exact attachment's snapshot is
admitted. This allows a fresh client process to classify retained final output
even after the runner has
removed the ended process. Cold starts establish channels through OPEN/OPENED.

A refusal is an answer, not a session failure: failed OPEN receives `REFUSED`.
The client needs both lifecycle metadata and an ordered `Established` geometry
before Ready. Draining metadata never authorizes input. A new instance retires
old parser/buffer/intent ownership atomically; the same ended instance cannot
resurrect, lose its continuity state, or produce a second Exit.

After EOF, final geometry/checkpoint output precedes an internal delivery marker.
`EXIT` is held with its descriptor and budget permit until the output frontier
has been transport-acknowledged and the control record reaches a real bounded
handoff, or scoped teardown releases it. Warm attach carries pending ownership
forward rather than declaring old output delivered. An ACK proves transport
receipt, not application display. The client retains partial output framing when
Exit arrives on the independent control stream and drains complete records
before exposing Exit. A client CLOSE owes no Exit; reused instances cannot receive
an old instance's completion.

**Ordered geometry.** `GEOMETRY` has a 22-byte payload:
`instance(u64) request_id(u64) outcome(1) reason(1) cols(2) rows(2)`.
Outcome 0 is Established (request ID 0, reason 0), 1 Applied (nonzero ID,
reason 0), and 2 Refused (nonzero ID, reason below). Instance IDs are nonzero.
Refusal codes are 1 InvalidSize, 2 NoPty, 3 ResourceLimit, 4 PtyResizeFailed,
5 ScreenPreparationFailed. A no-PTY OPEN retains its either-zero classification
and cannot acquire a PTY by resizing. Other dimensions must satisfy the terminal
resource policy. `PROTOCOL_ERROR` code 1 is ResizePipelineOverflow, an attempt
failure distinct from OPEN refusal or process exit.

Resize IDs are scoped to an attachment and channel instance. A client keeps
requested dimensions separately from committed dimensions, allows one request
in flight and coalesces later intent. The server reserves preparation/scratch
before ioctl, commits the model/request only on success, then orders Geometry
before output produced under the new size. A refusal reports the unchanged
committed geometry. The same refused intent revision is not retried on ticks,
repaint or warm reconnect; changing away and back is a new revision. Request-ID
exhaustion fails explicitly. DATA before a boundary is rendered before geometry
changes, even when both arrive in one callback batch.

`OUTPUT_GAP` has a nine-byte payload `instance(u64) cause(1)`; cause 1 is
PreviousConnectionOutputUnconfirmed. It marks an abandoned unacknowledged DATA
frontier from the previous connection: those bytes may or may not have reached
the application. Metadata-only replacement does not create a gap. An
unacknowledged gap survives another attachment without intervening DATA. Screen
snapshots can replace obsolete output; NoScreen records require
complete-record credit admission and retain their bytes across attach. These
bounds do not promise exactly-once replay.

At cutover, bootstrap geometry precedes retained output. Old correlated outcomes
become uncorrelated Established checkpoints; retained DATA keeps its geometry
boundaries, followed by the current checkpoint and new output. A gap follows
initial geometry and precedes the affected DATA. Only Screen DATA may drain in
byte slices. A NoScreen DATA record is at most 8197 bytes (8192 payload plus
framing); it needs room for the entire record under peer credit, offset headroom
and the 512 KiB local unacknowledged-output cap. Geometry and gaps also require
whole-record admission. Insufficient room retains ownership, and a credit or
capacity notification resumes draining without needing another process write.

The client validates declared record sizes before bulk deframing allocations.
Before lifecycle/initial geometry, retention is at most 64 KiB of DATA payload
and 256 events per channel. Unclassified channels additionally share an aggregate
512 KiB declared-byte and 2048-event limit across at most 240 unknown IDs.
Excess or contradictory known metadata fails explicitly. Portable same-instance
intent preserves desired revision, refusal and debounce eligibility across
reattachment; provisional early geometry cannot overwrite newer local intent.

A channel's own data stream carries the §1.5 records — DATA, ECHO_ACK,
GEOMETRY and OUTPUT_GAP — interleaved on the same ordered stream. An input
acknowledgement sent right after its output is applied only after that output has
reached the emulator, so local echo prediction has no "acknowledged before
shown" race to handle.

### 8.1 Updating the daemon

`channel_server.rs` (`DaemonUpdates`), `qshd/src/update.rs`,
`qshd/src/handover.rs`.

A client that carries daemon images sends `ABOUT_REQUEST` right after the
link is live and before it opens anything. This requires a compatible QSH
session; it cannot update a protocol-1 peer through a protocol-2 connection.
If a compatible peer does not answer the request, the client waits a bounded
time and treats the update facility as unavailable. A daemon started by a
service manager (`serve`, with or without `--system`) answers with mode `1` and
answers every offer `Managed`. The daemon works out its own checksum on the
first `ABOUT_REQUEST` (off the session's loop), never at start-up.

When the checksums differ the client sends `UPDATE_OFFER`. The daemon
decides by the same table `transport-ensure` uses (`version::replacement`),
with one difference: the offering session itself does not count as busy —
`others` is the active-session count minus one. A parked session (its
client silent, §4.2) is not active and does not count. Rows, in order:
`Managed`; `NotAllowed` (a session of another account — a connection still
in probation never reaches this code at all); `ArchMismatch`; `TooLarge`
(`MAX_UPDATE_SIZE` = 64 MiB); `UpToDate` (equal checksums); `DaemonNewer`
(no downgrades); `InProgress` (one update at a time, across all sessions);
`Busy`; otherwise `Accept`.

After `Accept` exactly `size` bytes follow on stream 14, raw. The transport
has no per-stream close, so the byte count is the end; bytes past it, and
bytes without an accepted offer in this session, are dropped. Thirty seconds
without a byte (`TRANSFER_STALL`) abandon the transfer.

The image's bytes are taken once the daemon has written them to disk; bytes
past the offered size, or with no transfer accepted, at once; and what a
transfer that ended early never took, when it ends (spec §4.10.3). So an
upload is paced by the disk, never more than a credit window ahead of it.

The client sends the image as the bulk class, 64 KiB at a time through the
stream's send gate: it waits while half a megabyte stands queued and
unacknowledged, and reports as progress what the daemon has acknowledged.
Keystrokes of a session on the same road go first.

The daemon stages the image next to its own binary (mode `0700`), checks
its size and sha256, runs `<staged> self-check` (at most 5 s; it prints
`{"build":…,"arch":…,"protocol":…,"protocols":[…],"handover_versions":[…],
"transport_features":[…]}`: build and architecture must match the offer,
`protocols` must include the current `PROTOCOL_VERSION`, `handover_versions`
the version of the handover this daemon is about to write;
`transport_features` is informational — nothing checks it). Last, it stops
admitting sessions — a handshake that arrives from here to the exec is
refused before msg2, and its client sends msg1 again, to the new binary —
and counts the other sessions once more. Any failure is
`UPDATE_RESULT Rejected` (or `Busy`), sessions are admitted again, and the
staged file is removed; the daemon, its binary and every session go on as
they were. Nothing has been announced at that point: a `Busy` never follows
a `Restarting`, and no session is cut for an update that does not happen.

Otherwise the decision is made. The daemon answers `UPDATE_RESULT
Restarting`, sends `RESTARTING` to every session (the offering one
included), and waits `RESTART_GRACE` (500 ms) — only for the record to reach
the clients; admission stays closed. Then, in order:

1. Every session — a parked one included — is counted into the drain
   (within 1 s) and then ends and reaps its channels (within 3 s). A channel
   process left running would become a child of the new binary that nobody
   waits for. The control socket answers `STATUS` and `ADD-CLIENT`
   throughout.
2. It stops taking control-socket requests (waiting at most 2 s for those
   in flight; a busy socket is `Rejected` with code `8 control socket
   busy`) and snapshots the admitted client keys: a request that arrives
   now waits, and meets the new process.
3. It `exec`s the staged file in place: same pid. The UDP socket and the
   listening control socket survive the `exec` (close-on-exec cleared on
   exactly those two, set on everything else), and a memory file whose
   number is in `QSHD_HANDOVER_FD` describes the rest as JSON: the handover
   version, the binary's path (read by the daemon from `/proc/self/exe`,
   never from a client), the staged path, the socket numbers, the control
   socket's path, the cache directory, the port, the name, and the admitted
   client keys — one-time keys from `ADD-CLIENT` included. The argument is
   `transport-resume`; no other command reads the variable.

The new process renames itself onto the binary's path, flushes the
directory, and carries on without binding anything. The server's static key
is on disk and does not change, so pinned fingerprints stay valid. Live
sessions do not survive: clients log in again. If the `exec` fails, the
daemon keeps running as it was, minus the channels it drained, and the
offering session gets `UPDATE_RESULT Rejected` after its `Restarting`; any
other way out short of the exec admits sessions again too. A
`transport-ensure` that meets the control socket mid-exec — its connection
closed unanswered with the socket file still there, or not answered in time
— asks `STATUS` once more half a second later.

A client that heard `Restarting` — or sent every byte and then heard
nothing for a while, or saw the link close — logs in again to the same
address with the same pinned key and asks `ABOUT` once more; only a matching
checksum counts as updated.

---

## 9. Threat model

What follows is what the code does, and what it does not. A section that
promised more than the code delivers would be worse than no section.

### 9.1 What the encryption gives you

Everything after the two handshake messages is ChaCha20-Poly1305. Between
two ends of this version the 18-byte header is its associated data
(`header-aad`, §2.6): contents are confidential, contents and header are
tamper-evident, and a modified `session_id` or `counter` fails the tag. If a
protocol-2 connection explicitly negotiates without `header-aad`, the associated
data is empty: the counter still
cannot be altered, because it is the nonce, but the `session_id` can; the
datagram then goes to another session, whose keys do not open it, and is
dropped. That leaves an attacker nothing a party on the path could not do by
dropping the datagram. A forged or corrupted datagram is dropped in silence.
A replayed one is caught by the 32 704-position window of §1.3 and dropped
before it can deliver data, advance liveness, or move the session.

Each direction has its own key, derived from a handshake that includes a
fresh ephemeral from each side on every connection. What that gives beyond
the above is a property of the Noise IK pattern, not of code in this
repository, and is not claimed here.

### 9.2 What an observer on the path still sees

Encryption hides what is in a session, not that one exists. Visible to
anyone who can watch the packets:

- two addresses exchanging UDP datagrams, and when;
- the version byte and the kind byte of every datagram — so handshakes,
  transport traffic, discovery and a daemon under load answering with
  cookies (§2.7) are trivially distinguishable;
- the `session_id` and the `counter` in clear, which means the number of
  datagrams sent and a stable identifier that persists across a change of
  address. Roaming is therefore *linkable* by an observer who sees both
  networks;
- the size of every datagram, and its timing.

Nothing pads transport datagrams and there is no cover traffic. Since this
implementation chunks data at 1024 bytes and packs small frames together
into datagrams of up to 1200 bytes, datagram sizes and arrival times still
follow keystrokes and output volume closely. And a live link sends a
keepalive PING every 1.5 s whether anyone is typing or not, so even an idle
session has a regular beat on the wire.

### 9.3 Trust on first use

Noise IK authenticates the server from the very first message — but only if
the client already has the right static key. Getting it the first time is
the weak point, and the code says so plainly: discovery
(`KeyRequest`/`KeyOffer`) is unauthenticated by nature, "there is nothing
yet to authenticate it with", which is exactly why `cli/src/trust.rs` shows
the key's fingerprint and asks a human before pinning it in
`~/.config/qsh/known_hosts`.

So: **whoever controls the network at the moment of first contact can offer
their own key** and be pinned. Compare it out of band if that matters to
you. Both daemons give you something to compare against: `qshd serve` prints
the SHA-256 fingerprint at startup, to stdout and to its log file
(`run_serve_command`), and a `transport-ensure` daemon prints the key itself
as `server-pubkey: <base64>` (`write_transport_ready` in `qshd/src/main.rs`)
— over the SSH session that started it, which is an already-authenticated
channel.

After pinning, discovery does not run again: it answers anyone who asks, and
doing it every launch would announce to a bystander that qsh lives here.
There is one exception, on a failure path the user is about to be told about
anyway: a server whose static key changed cannot complete an IK handshake
against the old one, and the transport reports that as silence — which is
also what a stopped daemon looks like. `changed_key_after_silence` asks once
at that point, so a changed key produces a loud refusal naming both
fingerprints instead of being swallowed into "unreachable".

### 9.4 If your SSH key is stolen

On the signature path the SSH key *is* the identity. Whoever holds it can
authenticate to qshd exactly as you would — and can also log in over SSH,
which is the same key and the same consequence. There is no second factor
here.

What the theft does **not** give:

- **replay elsewhere.** The signature covers `"qsh-auth-v1" || handshake_hash`
  for a version 1 record, or `"qsh-auth-v2" || handshake_hash || nonce ||
  login` for a version 2 one (§3.2.1). Either way the handshake hash is
  unique per session (§2.5), and a version 2 signature also commits to a
  nonce minted fresh for this handshake alone. A signature captured from
  one session verifies against no other, and a signature taken by some
  other protocol that talks to your agent does not verify here.
- **the key itself, to the server.** The daemon sees a public key and a
  signature. Signing happens in `ssh-agent` or from a local key file
  (`crates/sshauth`), never on the server.

Revocation is `authorized_keys`: remove the line. The file is re-read on
every attempt, so a removed key stops getting in immediately — a warm
reattach brings a new handshake with a new hash and goes through probation
again, so it is refused too. But nothing re-checks the key of a session that
is already running: **removing a key does not close the sessions it
opened**, and one of those can sit there for a day (`SERVER_DEATH_AFTER`) or
be retained for an hour after its client dies. To end them, stop the daemon.

### 9.5 If the server's static key is stolen

The server's static key is its whole identity under IK. Where it lives
depends on the daemon: `qshd serve` defaults to `~/.config/qshd/host_key`
(`parse_serve_args` in `qshd/src/serve.rs`, overridable with `--host-key`),
while a `transport-ensure` daemon keeps it in its cache directory as
`transport_server_key.bin` (`default_transport_key_path` in
`qshd/src/main.rs`).

Whoever holds it can impersonate that server to any client that
has pinned it: the client's handshake completes, and the client will then
send its SSH signature — which the impostor can read but cannot reuse
anywhere else (§9.4) — and afterwards everything the user types goes to the
impostor. Pinning does not help here; the pinned key is the stolen one.

`qshd serve` treats the file accordingly: `load_or_create_transport_key`
creates it `0600` atomically, and at every startup permissions wider than
owner-only are tightened to `0600` **and warned about loudly**, because
tightening does not undo a past leak. The daemon still starts — refusing to
start over a problem it can fix itself would be the worse failure — but the
warning says to consider deleting the key and letting a new one be created.

Note the asymmetry: stealing the server key does not authenticate a
*client*. A signature client still has to produce a valid signature over the
new handshake's hash, and the daemon that checks it is the one holding
`authorized_keys`.

### 9.6 What a change of address can and cannot do

Because the address is not an authenticator, in either direction. The seven
conditions in §5 are the whole story, and the decisive ones are the second,
third and fourth: the datagram must decrypt under this session's keys, with
its own counter as the nonce and the associated data of §1.1; it must
carry a counter above every counter seen so far; and it must not be a
replay. (The first, a matching `session_id`, is in the clear and proves
nothing on its own — it only says which session the sender is aiming at.)

**Against an off-path attacker this holds absolutely.** Without the session
keys they cannot produce a datagram that decrypts, so they cannot move
anything. Copying a genuine datagram they observed does not help either: the
original has already arrived and taken that counter, so the copy is a replay,
`ReplayWindow::accept` rejects it, and the migration check never runs.

**Against an on-path attacker it does not.** Say it plainly: someone who can
*suppress* the original and forward the copy from their own address is not
sending a replay — they are delivering a genuine, never-yet-seen datagram
with a new maximum counter, from a new address. Every one of the seven
conditions in `Connection::on_transport` is satisfied, and the server moves
the session to them. There is no validation of the new path before the move —
no equivalent of QUIC's `PATH_CHALLENGE` — and §9.2's own admission that an
on-path attacker can drop packets is exactly the capability this needs.

What survives that is confidentiality and integrity: the attacker still
cannot read or alter what passes through them, and cannot inject anything
of their own, because none of that is within reach without the keys. What
they gain is the traffic's destination — they can hold the session's return
path, and drop it.

One more thing this deliberately does not defend against: when the peer
genuinely does appear at a new address, the session follows it. That is the
feature, and a NAT rebinding exercises it too.

**What a peer can draw, and to where.** Every reply a daemon sends goes to
the session's current peer address — the source of the latest datagram with
a new maximum counter, as above. A peer that holds the session keys can
therefore aim the replies at any address by forging its source, and this
includes an unproven peer in probation (§9.7), whose Noise key is
throwaway. So what one *frame* draws is kept small:

- a `PING` draws its `PONG` and at most one `CREDIT` — only for a stream
  whose sender may be stopped, the streams taking the copy in turn, each at
  most once per `rto` (§7). The copy rides inside the `PONG` (§1.4): a
  39-byte `PING` draws at most 45 bytes of its own, in one datagram.
  Whatever earlier datagrams left owed rides with it (below): up to
  `ACK_EVERY − 1` held `ACK`s, 18 bytes (63 bytes in all; measured:
  57 bytes with three held `ACK`s and no copy), and 6 bytes for each
  `CREDIT` held that is not urgent yet, one per stream at most, each earned
  by real consumption. Before that bound every stream that might be stopped
  added its own `CREDIT` to every `PONG`, each a datagram of its own then;
  with a `Reset` on each of the 256 stream numbers, one `PING` drew 257
  datagrams, 10 279 bytes;
- a `Reset` from a client draws nothing at all: a server drops it whole
  (§7). Taken, one on a stream nobody consumes left that stream "possibly
  stopped" for good, and that was the lever for the fan-out above;
- a `CREDIT` draws no reply of its own. A raised limit lets the daemon send
  output its session already has queued — nothing in probation, where no
  backend runs yet; after it, the proven user's own output, sent where that
  user's datagrams come from;
- a `DATA` draws its `ACK`, at once or held for a ride (§7), and — once its
  stream's limit has grown enough, or lands exactly on an older one — the
  `CREDIT` announcements and repeats above, same as any other growth.

**Answers are built per datagram.** A datagram is answered once, whatever
it packs: one `PONG`, for its last `PING` — the pinger takes a `PONG` as the
answer to that `PING` and every older one it still has out — carrying
at most the one `CREDIT` copy above; one `ACK` per stream its `DATA` (or, to
a client, `Reset`) frames named, for the point the last of them left; one
`CREDIT` per stream at most; and one `PathProbeAck`, for its last
`PathProbe`, alone, to the datagram's own source. All but the probe answer
are packed together (§1.4). Leaving aside `CREDIT`s, which a stream earns
only by having `CREDIT_UPDATE_STEP` taken since its last one (or, on a
client, from a server's `Reset`), what one datagram draws is no larger than
it: an `ACK` (6 bytes) per stream it named with a `DATA` (8 bytes at
least), one `PONG` (5 bytes) however many `PING`s (5 bytes each), and one
datagram's header and tag (34 bytes) for the answer to its source.
Measured from a peer in probation: a 1 384-byte datagram of 270 `PING`s
draws one 39-byte `PONG` (before this rule: 270 datagrams, 10 530 bytes, to
whatever forged source it moved the session to); 270 `PathProbe`s draw one
`PathProbeAck`; 160 empty `DATA` frames draw one `ACK` on one stream, and
160 `ACK`s in one datagram on 160 streams. With `k` streams that may be
stopped the same 270 `PING`s draw one 45-byte datagram, where they drew
270 + k datagrams (526 with all 256). An answer may also carry what earlier
datagrams drew and did not send (§7, Acknowledgements): the points of
in-order `DATA` held for a ride — at most `ACK_EVERY − 1` of them, one per
stream, since the count of such `DATA` runs across the connection — and
`CREDIT`s not yet urgent. Those datagrams drew nothing themselves, and what
nothing carries goes alone within `ACK_DELAY`, still one datagram for
several; so the total stays at most one answer per datagram received.

The price of the `PING` bound is liveness in a case no honest peer makes:
with `k` streams that may be stopped, a stream whose `CREDIT`s were all
lost waits up to `k · max(rto, PING_INTERVAL)` for its copy — each stream
takes its turn only once its own `rto` has passed since its last copy, and
`rto` grows with the round trip and with back-off up to
`RETRANSMIT_CEILING` (15 s). An honest stop is one or two streams.

### 9.7 What probation does, and what it does not

Probation (§3.3) is a structural boundary: an unproven peer holds a datagram
route and a note of the token it named, and nothing else (what it can make
the daemon send, and to where, is in §9.6), and the code that
reattaches, replaces and evicts sessions is not reachable from where it
stands. It also bounds what an unproven peer can cost in memory and slots:
128 concurrent probations, 16 per source group, 8 KiB of record buffer,
64 KiB of early data and 64 KiB of out-of-order data each, for at most 5
seconds. A session's datagram route — the queue between the socket loop and
its bridge or probation — holds at most 1 MiB, each datagram costing its
length plus 64; past that a datagram is dropped, as the network would. While
the connection is in probation its route holds 128 KiB, raised to 1 MiB when
the proven connection is handed to its bridge: a probation reads nothing
while its proof is verified, and 128 probations at a full megabyte would be
128 MiB.

What it does not do:

- **it does not stop a flood by itself; the return-address check does.**
  Without load, `Connection::accept` runs a full Noise handshake on every
  `HandshakeInit`, before any cap is consulted — *two* on a daemon running
  both gates with a non-empty allowlist (§3.1.1). A flood makes the daemon
  under load (§2.7): from then on a msg1 costs one MAC and a 35-byte answer,
  and only a msg1 behind a valid cookie — proof that its sender receives at
  its address — reaches `accept`. What a flood from forged addresses can
  still cost is what stays under the thresholds: at most 64 handshakes a
  second, and about half the probation table. An attacker at real addresses
  gets cookies like anyone else, and is held to 20 proven handshakes a
  second per address (§2.7) and by the caps below.
- **it does not authenticate the client's Noise key.** It is deliberately
  throwaway on the signature path.
- **it does not help against a stolen SSH key.** A stolen key passes
  probation on the first try.
- **the token a peer names is not checked.** It only holds removal back
  (§4.2): the GC spares that token's retained session one pass, and
  eviction takes other retained sessions first. The token is chosen by
  the client and travels only inside the encrypted msg1, but msg1 carries
  no freshness: anyone who has seen a client's msg1 on the path can send
  it again, verbatim and from any address, and name that client's token
  without reading it. What that buys is bounded by the table above — at
  most 128 tokens at a time, each held for 5 seconds unless the replay is
  repeated — and amounts to one more GC pass for a dead session, or an
  eviction moved onto another retained session. Nothing can be ended or
  taken over this way.
- **the per-source cap is per IPv4 host or native IPv6 /64.** Clients behind
  one NAT or within one IPv6 /64 share one budget of 16 — which is why the
  number is not smaller.
- **the table itself is a resource four real source groups can exhaust, with
  a forged flood's help.** `MAX_PROBATION` = 128 across all sources,
  `MAX_PROBATION_PER_SOURCE` = 16: eight source groups that receive at their
  addresses, sending handshakes fast enough to claim their sixteen slots
  each, occupy the whole table between them. Forged ones cannot get past
  the cookie once the daemon is under load, but they can hold the half of
  the table the load threshold leaves them: load begins only above 64 seats,
  so a forged flood slow enough to stay under the handshake rate — about 13
  msg1s a second, one per seat per 5 s — keeps 65 seats taken, and four
  real source groups take the other 63. Every `HandshakeInit` past the cap is
  dropped in silence (§3.4). Under load a client built before the
  return-address check is refused whatever the table holds (§2.7): the
  price of the defence.

Past probation, the session table (§4.2) has the same shape of limit, now
split into two caps rather than one global number. `MAX_SESSIONS_PER_OWNER`
= 16 bounds one account: at its own cap, a caller only ever displaces its
own oldest retained backend, and is rejected outright only once every one
of its own backends is live — one authenticated account can neither be
locked out by another's full table nor forced to evict a session that
isn't its own. `MAX_SESSIONS_TOTAL` = 128 bounds the daemon as a whole: an
account still under its own cap but blocked by this ceiling evicts the
oldest retained backend of *any* account instead of being rejected. Either
way, a backend that merely falls silent still counts against both caps for
up to `SERVER_DEATH_AFTER` before its `RETAIN_AFTER_DEATH` window even
starts — up to a day, in the worst case, before a slot frees on its own.
Reaching either limit needs backends that already passed authentication, so
it is not the anonymous flood the probation table is exposed to; it is
the same shape of ceiling one step later, and worth knowing about for the
same reason.

### 9.8 What the protocol assumes about its environment

- **`~/.ssh/authorized_keys` on the server is correct and trusted.** It is
  re-read on every attempt. **Options on a line are not honoured — they
  refuse the key.** If you rely on `command="…"`, `from="…"` or `restrict`
  to confine an SSH key, understand that qsh does not implement them: it
  refuses such a key rather than admitting it unconfined. A key admitted by
  qshd gets a channel running `$SHELL` as the user the daemon runs as, with
  that user's full privileges.
- **`ssh-agent`, or the key file, is trusted to hold the private key.** The
  agent will sign whatever it is asked to; the domain prefix is what keeps a
  signature taken here from being useful elsewhere, and vice versa.
- **The host key file stays secret** (§9.5), and its directory with it.
- **The OS lets a socket queue enough.** Every transport socket — the
  daemon's or client's — asks for `SOCKET_BUFFER_REQUEST` = 4 MiB
  each way: one stream's window is about 590 KB in Linux's accounting, and
  several of them plus what arrives while a client is paused is about 3 MB. A
  burst the kernel cannot queue is dropped without a word and waits for a
  retransmit. What was granted is logged — the daemon's log (`udp buffers:
  receive 4194304 requested, N granted; send …`) and `qsh --verbose` — as the
  OS reports it: Linux reports twice what
  it lets the data use. An unprivileged process gets at most
  `net.core.rmem_max` / `net.core.wmem_max` (212 992 bytes by default on
  Linux, reported as 425 984); where the log shows less than asked, raise
  them (`sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304`, and
  in `/etc/sysctl.d/` to keep it).
- **The control socket is its owner's alone.** `transport-ensure`'s control
  socket (`control.sock` in the cache directory) is bound inside a fresh
  `0700` directory, made `0600` and only then moved to its name: there is no
  moment when the umask's permissions let anyone else connect.
- **The local session store is yours alone.** `~/.config/qsh/sessions` holds
  the tokens that identify sessions on the server (`0700` directory, `0600`
  files). A token alone admits nobody — a reattach still has to pass the
  allowlist or probation — but anyone who can read your files can also read
  your SSH key, which is the real prize.
- **A session outlives its client, on purpose.** A silent session stays
  routable for `SERVER_DEATH_AFTER` = 24 h, and a backend retained after an
  unexpected death survives `RETAIN_AFTER_DEATH` = 1 h. Everything running
  inside it keeps running.
- **The allowlist path assumes its bootstrap channel.** Where it is used —
  only in a `transport-ensure` daemon — a key gets onto the list over SSH or
  through that daemon's local control socket, so it is exactly as
  trustworthy as SSH access to that host and local access to that socket.
  `qshd serve` does not use that path at all. Note that this does not make
  `transport-ensure` the laxer of the two: it runs the signature gate as
  well, against the same `authorized_keys`, so both gates guard it (§3.1.1).
- **Neither end is defended against its own host.** Someone who controls the
  server can read every session on it; someone who controls your machine can
  read your key, your tokens and your terminal. Nothing here changes that.

Terminal geometry, admission refusals, payload caps and qualified storage bounds
are documented in [Terminal resource policy](terminal-resources.md).
