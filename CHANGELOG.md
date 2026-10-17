# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-10-17

### Changed

- Limit the workspace to the console client, daemon and their shared libraries.
  Remove the embedding bindings, tmux controller and client update policy.
- External SSH signers now return standard SSH signature blobs.
- Run unit and integration tests through nextest with bounded concurrency.
  Enable the current-client/current-daemon screen-flood regression by default.

### Public repository preparation

- Start the public branch from one reviewed source snapshot. Legacy history is
  retained in a local-only archive and is not part of the public branch.
- Replace committed SSH private-key fixtures with freshly generated temporary
  test keys. Use the maintainer's public GitHub identity in package metadata.
- Provide an English project overview, CLI guide, and privacy-check procedure.
  Require secret scanning and manual privacy review before every GitHub push.
  Scan assembled release packages before publication.
- Keep protocol version 1 and existing daemon compatibility.

### Fixes

- Disable terminal echo on SSH command PTYs to keep command replies intact.
- Fall back to SSH immediately when a direct UDP connection is refused.
- Default daemon-installation approval to Yes and adapt download progress to
  the terminal width.
- Build the daemon on macOS using an unnamed temporary handover file and
  `/dev/fd`; retain Linux memory files and verify handover behavior on macOS.
- Keep CI compatible with the current Rust atomic API and account for all
  subprocess-isolated tests.

## [0.4.1] — 2026-10-17

### qsh

- Interactive SSH connections can request approval to install a missing `qshd`
  from the matching GitHub release. Linux/Darwin x86_64/aarch64 images are checked
  with SHA-256 and cached locally. SFTP upload, verification, and atomic
  publication have separate deadlines and support cancellation. Managed system
  services are not replaced; background recovery never asks, downloads, or installs.
- UDP recovery no longer waits for SSH or its backoff: handshake packets repeat
  every 500 ms, and immediately failing rounds are limited to one per second.
  SSH independently retries addresses with knocking and 1–30 second delays,
  passes the discovered port and process-key authorization to UDP, and is
  cancelled when UDP recovers. `Ctrl-] r` removes the SSH delay during recovery.
- Client logging is always enabled, rotating after 1 MiB to `log.1`. `--verbose`
  increases detail. Startup records version/build; exit records the status.
  While rendering, stderr is redirected to the log instead of the terminal.
- Login diagnostics distinguish UDP send errors, silence, key discovery without
  login, incompatible replies, and IPv6-only destinations. Refusal reports the
  claimed account and offered key fingerprints; exit 12 points to the log.
  Applicable macOS errors include a hint about Local Network permission.
- Every address in one invocation uses the same expected server key. An unpinned
  address is remembered only after an authenticated handshake; conflicting keys
  stop with exit 11 without silently overwriting a stored record.
- Sessions use the alternate screen and restore the terminal on exit, signals,
  and suspension, replacing the outer-terminal scrollback behavior in 0.4.0.
- `Ctrl-] [` opens client emulator history. `--history N` sets the capacity
  (default 10000; zero disables it). Navigation stays local, incoming output
  does not move the selected view, and `q`/Escape returns live. Stream resets
  clear history.
- Connection and help panels have spacing, framed hints, and a dimmed background;
  borders adapt to color, monochrome, and ASCII-only terminals. Narrow terminals
  clip safely.

### qshd

- Daemon logging uses the shared UTC/PID/level/component format and includes
  transport records in `qshd.log`. The daemon retains its independent sink,
  2 MiB rotation, and operation after forking and dropping privileges.
- `qshd serve` also writes stderr for journald, including system-mode refusals.
  Documentation and acceptance checks follow the new format; log-injection
  fields are sanitized.

### logging

- A shared crate supplies millisecond UTC timestamps, PID, level, component
  filters, and a rotating file sink.
- Every line of a multiline record has its own header; control characters are
  escaped. File-open or write failures do not stop the application. New files
  use mode 0600 and directories 0700.
- `KnockStep` debug formatting hides knock ports and payloads.

## [0.4.0] — 2026-09-30

Still pre-1.0: interfaces may change between minor versions.

### qsh
- Several addresses with per-address settings: `host[:port][,ssh[=port]][,nossh][,knock=STEPS][,noknock]`,
  plus `-l`, `-p`, `--ssh[=N]`, `--knock STEPS` and `--no-password`. An address's own port now wins over `-p`.
- A connection ladder per address: qsh directly; if that does not answer or does not take the keys and the
  address has SSH, knock, log in over SSH and bring the installed `qshd` up with this run's key; then qsh again
  on the port the daemon reports. Progress is printed to stderr before the session starts; exit code 12 lists
  every address and why it failed.
- A server that refuses every key is now exit 12 (all addresses failed), not 10; 10 is only for keys that could
  not be loaded.
- An account with no SSH key at all still gets to the ssh step: with nothing to sign with, the direct qsh login
  counts as refused and an address with ssh goes on (a password-only ssh account). A key file that exists but
  will not load is still exit 10. `--no-password` also keeps the passphrase question for qsh's own key files
  from being asked.
- SSH host keys come from `~/.ssh/known_hosts` (hashed entries, patterns, `@revoked`); an unknown one is asked
  about with its fingerprint and remembered. Questions go to the terminal (`/dev/tty`).
- A link that dies no longer ends the run after two hours of waiting: once the transport gives up on it
  (45 s), the client walks the address ladder again in the
  background -- the address that last worked first, nobody asked anything -- and returns to the same
  session, screen included. Rounds that get nowhere are retried after 1, 2, 4, 8, 16, then 30 s;
  `Ctrl-] r` reconnects at once. A session the server no longer has (the daemon restarted) ends the run
  with exit code 13; a changed server key, with 11.
- The escape prefix is `Ctrl-]` now (`Ctrl-^` needs Shift on a Mac); `--escape ^X` picks another control
  key, `--escape none` turns it off. After the prefix: `.` leaves -- the session stays on the server --,
  `s` opens the connection state, `h` hides or shows the status line, `r` reconnects, `?` lists the keys,
  the prefix again sends it; any other key is swallowed with it, an arrow or an `Alt` key whole.
- A status line on top: the address in use (with several addresses), the latency,
  and -- on red -- how long the link has been silent or where it is reconnecting to. `--status off` goes
  without it. The remote side gets one row less while it is shown; mouse reports are moved to match, and
  the lines that scroll off the top still reach the terminal's own scrollback; the line does not scroll into it.
- `Ctrl-] s`: every road with its state in command-line order, the one in use in colour; `Enter` on a live
  spare moves the session there.
- A run that returns to a kept session (the last one left with `Ctrl-] .`, or was killed) binds the shell
  the server still runs instead of asking for a new one; it used to be refused (`channel already open`)
  and end at once.
- A terminal without colour gets output without colour, attributes only: `TERM=dumb`, `vt1*` and `vt2*`
  (`vt100`, `vt220`), `*-mono` and `*-m`.

### ssh
- Logs in by a plan of methods tried in one connection, the way OpenSSH walks its
  identities: ssh-agent keys, key files (a passphrase is asked only when the server
  would take the key), passwords and keyboard-interactive, each asked through the
  caller's prompter. Time spent answering is not counted against the connect timeout.
- Knows several host keys per address and offers their types first, so a server with
  more than one host key is no longer mistaken for a changed one.
- Passwords, passphrases and PEM text are held in zeroizing buffers.
- A connection lost during login is now reported as a connection error, so a caller
  may try again; only the server's own refusal (its goodbye, such as "Too many
  authentication failures", or no method it would take) is a refused login.

### bringup
- New crate: brings an installed `qshd` up over SSH for a qsh login. It knocks and
  logs in (the `ssh` crate's login plan), finds the daemon in the user cache
  (`~/.cache/qsh/qshd-<version>-<arch>`, the newest runnable one, on Linux), else on
  `PATH`, else in `~/.local/bin`, `/usr/local/bin`, `/opt/homebrew/bin` or
  `~/.cargo/bin` (a non-interactive SSH session's `PATH` often lacks them), runs
  `transport-ensure` with the caller's Noise key and returns the ports the daemon
  listens on. Commands run under `sh` whatever the login shell; a hang is bounded
  and can be cancelled. A qshd already running as a service (the system one or the
  account's own) is reported instead of starting a second daemon; it is recognised by
  its name only, `qshd.service` (systemd) or `me.qsh.qshd` (launchd).

### connect
- New crate: the address ladder (qsh directly, then SSH to bring the daemon up, then
  qsh again) and the schedule a client reconnects on, as state machines with no I/O.
  The console client uses these state machines.

### qshd
- `transport-ensure` reports in `TRANSPORT-READY` the port the daemon actually listens
  on: a live daemon's own port rather than the one the call asked for, and a fresh
  daemon's bound port without the unbound `--default-port`.

### Security
- A second way in: after the ssh step, `qsh` logs in over qsh with no signature. The
  daemon it started (or found started that way) was handed this run's Noise key with
  `--client-pubkey`, and that key alone lets the login in. Such a login is exactly as
  trustworthy as the ssh login that set it up, a password included; the key comes off
  the daemon's list when the connection it let in ends. A `qshd serve` service never
  admits a key this way.
- Text from the server before the session starts -- the ssh step's failure text,
  qshd's warning, keyboard-interactive names, instructions and prompts -- is printed
  with control characters defused: line breaks and tabs become spaces, every other
  control character (C0 with ESC, DEL, C1) becomes `?`. A server cannot move the
  cursor, retitle the window or clear the screen from a line of `qsh`'s.
- A signal while a secret is being asked (SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGTSTP)
  puts the terminal's echo back before it takes effect, as OpenSSH's `readpassphrase`
  does; a stop turns echo off again on its return. A terminal whose echo will not go
  off is not read from at all.
- `~/.ssh/known_hosts` patterns are matched in at most the pattern's length times the
  name's steps, so a pattern full of `*` cannot hang the client; a line that is not
  UTF-8 is skipped alone, not the whole file, so it cannot hide the `@revoked` lines
  around it; and a host or key type with whitespace, a comma or `#` in it is never
  written to the file.

## [0.3.0] — 2026-09-29

Still pre-1.0: interfaces may change between minor versions.

### Added

- **Negotiable transport features.** msg1 now ends with the features the
  client offers and msg2 with those the server enabled, 32 bits each
  (`transport::Features`: `header-aad`, `stream-credit`, `offset-wrap`),
  after the bytes every older build reads and nothing it looks at. A field
  cut short reads as nothing; unknown bits and bytes after a field are read
  past. This build implements all three.
- **Streams go on past 4 GiB** (`offset-wrap`, negotiated). Between two
  ends of this version a stream offset is a 64-bit count inside the process
  and travels as its low 32 bits, read back as the nearest full offset
  (RFC 1982, as QUIC expands packet numbers); a stream no longer stops at
  `OFFSET_LIMIT`, and the connection is no longer dropped there. A fast
  recovery's point is a full offset too, so recoveries across 2³² end on
  time. A receiver with it takes nothing, `DATA` or `Reset`, past the full
  offset 2⁶², so crafted frames cannot walk a stream to the end of the
  64-bit count. With a peer built before it the limit, and the reconnect
  at it, stay as they were.
- **Stream credits** (`stream-credit`, negotiated; the `0x09 CREDIT`
  frame). Between two ends of this version every stream has a window of
  512 KiB past what its consumer has taken: a slow or stuck consumer holds
  back only its own stream, with nothing in flight and nothing resent,
  while the other streams, the PINGs and the road checks go on.
  `Connection::set_stream_consumption`, `set_default_consumption`,
  `on_consumed` and `unconsumed_streams` say when bytes count as taken (on
  delivery by default). A limit announcement that gets lost is repeated,
  and carried by the PONGs (one copy per PONG, each stream at most once
  per `rto`), whenever the sender may be stopped at the older limit. Peers
  built before it run without limits.
- **The daemon counts consumption where bytes leave it.**
  `SessionBackend::consumption` says whether a backend reports what it
  takes (`SessionIo::consumed`, `SessionIo::consumption_reporter`,
  `SessionOutbound::Consumed`) or the bridge counts what it hands over; a
  warm reattach swallows the reports of bytes the replaced connection
  delivered, so the new connection's credit starts from its own bytes.
- **What a connection agreed, where to see it.** `StdClient::features`,
  `TmuxSession::transport_features` (a new `TransportFeatures` record;
  socket buffers read 0 until they are sized), a daemon log line per
  session (`session <id>: transport features …`), `qsh --verbose`
  (`transport features: …`), and `transport_features` in `qshd
  self-check` (what the build implements; older daemons skip the field).
- **`TmuxSession::rename_session`, `rename_window` and `new_window_in`** —
  control-channel commands for renaming a session (by id or by name) and a
  window, and for opening a window in a given session rather than the
  client's current one. Names go after `--`, so one that starts with a dash
  is a name, not a flag.
- **Window activity marks.** On tmux 3.2+ the control channel subscribes to
  every window's `#{window_activity}` and marks a window with new output
  (`TmuxWindowView::activity`, and `TmuxSessionView::activity` for any of
  a session's windows) -- except the window the terminal shows, which the
  platform names through `TmuxSession::set_current_session`. Selecting a
  window clears its mark; `%session-window-changed` now refreshes the tree.
  No tmux option (`monitor-activity`) is changed. The terminal's session
  follows tmux's own `%client-session-changed` for the shell's client, and
  starts as the session the attach names.
- **Moving a session onto a road by hand.** `Connection::use_road`,
  `StdClient::use_road` and `TmuxSession::use_road(label) -> RoadSwitch`
  move a live multipath session onto one of its verified roads at once, with
  a forced PING so the daemon follows after one packet. Nothing is pinned:
  automatic moving leaves a chosen road only on its two triggers (see
  "Changed"), so the chosen road keeps the session for as long as it carries
  traffic. The daemon is unchanged.
- **`transport::testnet`, a deterministic network simulator** (feature
  `testnet`, always on in the crate's own tests): a client and a server
  `Connection` over simulated roads in virtual time -- per-direction delay,
  jitter, loss, reordering, bandwidth and queue limit, a seeded SplitMix64,
  the drivers' timer and handshake-retransmit rules -- with delivered bytes,
  events, per-kind frame counts, stream tails and the standing queue of each
  link (`Sim::link_backlog`) to assert on; a long run may count what it
  delivers without holding it (`Sim::delivered_len`,
  `Sim::forget_delivered`), and a NAT may give the client a new port on a
  road (`Sim::rebind_client_port`). A side's consumer of a stream may stall
  or read at a rate (`Sim::set_consumer`), with the peaks of what it did not
  take and of what each side held out of order to assert on.
  `Connection::on_timeout_if_due` and `Connection::state` are new public
  methods; `peek_frames` and `ping_unanswered` exist for tests only.
- **Stream classes.** `StreamClass::{Interactive, Bulk}` and
  `Connection::set_stream_class`: a flush serves interactive streams first,
  round-robin, 4 segments a turn, and bulk streams after them, at most 32
  datagrams per flush. A stream nobody declares is interactive.
- **A hard cap on a stream's tail** (`SEND_HARD_CAP`, 4 MiB,
  `Event::SendBufferOverCap`): a net under the send gates. A daemon stream
  with a screen model past it is dropped and repainted; any other stream is
  kept and logged once.
- **Send gates** (`transport::send_gate`): a per-stream gate a producer can
  look at or wait on, closed at a high mark of the stream's queued and
  unacknowledged bytes and open again at a low one (128/32 KiB for a screen
  channel, 512/256 KiB for anything else). Bytes a backend has handed to the
  bridge (`SessionIo::send`) and the bridge has not taken yet count too.
  `SessionIo::send_gate`, `drop_send_gate`, `close_send_gates`,
  `set_stream_class`; the daemon's bridge refreshes the gates after every
  wake-up -- while the client is gone it opens them all at the end of every
  turn, though bytes a backend hands over in between still count until the
  bridge takes them -- and tells a screen channel `SessionInbound::Writable`
  when its gate opens. Every gate closes for good when the session's io
  goes, however its backend ends (a panic, the daemon's runtime dropped), so
  no producer is left waiting on one. A channel that goes away puts its
  stream back in the interactive class.
- **`StdClient::send_bytes_bounded`, `set_stream_class` and `is_gone`.** A
  producer can hand bytes over through a per-stream gate that closes at
  512 KiB queued and unacknowledged (bytes handed over and not yet taken by
  the driver count too) and opens at 256 KiB. A refusal says why
  (`SendBlocked::{Full, Gone, OnDriverThread}`); from a callback on the
  driver thread, or once the driver has ended however it ended (a panic in a
  callback included, which reports no `Closed`), it comes at once. An FFI
  daemon-image upload goes through it as the bulk class, reports
  acknowledged bytes as progress, and ends as `Lost` at once when its
  driver is gone. `transport::test_peer` (feature `testnet`): a loopback
  server that stops acknowledging, for other crates' tests.
- **Transport sockets ask for 4 MiB of buffer each way** and say what the
  OS granted: the daemon's log (`udp buffers: …`, for a socket it bound and
  for one an update handed over), the FFI connection statistics, and
  `qsh --verbose`. A window's burst no
  longer overflows Linux's default 208 KiB and waits for a retransmit
  where the OS allows more (`docs/qshd-service.md`, Socket buffers).

### Changed

- **Frames are packed into datagrams of up to 1200 bytes.** A flush, a
  PING, a PONG and the ACKs and CREDITs a side owes share datagrams: a
  full DATA segment carries up to 22 six-byte frames beside it, and an
  ACK rides the data going the other way. A road check and its answer
  still travel alone, as an older receiver needs. Peers built before this
  understand packed datagrams; their own stay one frame each.
- **Acknowledgements are delayed and ride other traffic.** A receiver
  sends an ACK for every four DATA frames, or with the next datagram it
  sends anyway, or 20 ms after it was owed -- at once for a DATA past a
  hole, a repeat, the DATA that fills a hole, a `Reset`, and room for a
  sender stopped at its limit; a PONG is never held. Bulk data draws
  about a quarter as many acknowledgements. An ACK counts for up to four
  segments in the congestion window's growth, so the window grows as
  before -- except in the round trip after a retransmit timeout: until
  what was in flight at the timeout is acknowledged, an ACK counts for one
  segment of slow start (RFC 3465 §2.3), so the ACK that fills the hole
  and covers everything the receiver held behind it lets two segments out,
  not five. Older peers still acknowledge every DATA and are served as
  before.
- **The daemon's channels report what they take.** A channel's input
  counts as consumed once its process has it, the update image once it is
  on disk, a control record once applied, and anything dropped at once --
  so a process that does not read its input holds back only its own
  channel's stream, by one credit window, while the session goes on.
- **Transport encryption no longer goes through snow's transport state.**
  The two transport keys come from the Noise handshake's split and seal with
  `chacha20poly1305` directly -- the same nonce (four zero bytes, then the
  counter little-endian), the same key for each direction, the same refusal
  of counter 2⁶⁴−1 -- so with an older peer the bytes on the wire are those
  of every earlier build, pinned by reference vectors taken from snow.
  `docs/protocol.md` said the 18-byte header was the AEAD's associated data;
  it was not, and the document now says so.
- **A congestion window.** A connection no longer puts a whole 256 KiB
  window on the road at once: it starts with 10 segments, grows by slow
  start and congestion avoidance (RFC 5681), and after a retransmit timeout
  drops to one segment and resends only the oldest one. Three duplicate ACKs
  resend the lost segment at once and recover by NewReno (RFC 6582), so a
  queue smaller than the window no longer turns a transfer into a crawl:
  8 MiB over 64 KB/s with a 64 KiB queue took ~860 s, now 140 s. A fast
  retransmit that reordering set off is undone and the duplicate threshold
  learns the road's reordering, so a road that holds datagrams back does
  not pay for losses it never had. An ACK within 2 ms of the road's base
  delay (`HOST_SLACK`) still answers a repair: on loopback and on a LAN the
  base carries the hosts' own batching, and real losses were taken for
  reordering there -- 1 MiB echoed over loopback took 1.5-2.5 s instead of
  a fraction of a second. A move starts the window afresh on both sides:
  the daemon's when it follows its client to a new address or port, as
  the client's when it moves -- onto a faster road the daemon's old base
  delay had its genuine timeouts undone, and after the client's own new
  socket what the daemon had sent to the old port came back only a
  segment per round trip. Nothing changes on the wire.
- **A bulk transfer keeps its own queue short.** A round trip more than
  500 ms above the road's base delay -- the smallest round trip of the last
  ten minutes -- halves the congestion window, as a loss would, at most once
  per round trip. The image upload over a 64 KB/s uplink no longer stands
  4 s deep in the modem's buffer, and the PINGs, road checks and keystrokes
  behind it wait about half a second. The undo of a spurious fast
  retransmit measures against the same base delay, so a real loss behind a
  standing queue is no longer taken for reordering. When no round trip has
  come near the base for nine minutes -- a transfer whose queue never drains
  -- the window probes the road: two segments until the queue is gone and
  the road is measured, then a slow start back to what the road carries
  without it. Without the probe the base crept up with the queue, 0.5 s to
  0.9 s over half an hour; a probe costs its minute under 1 % on a 100 ms
  road. Neither the signal nor the probe touches a sender with nothing
  waiting: a terminal session whose road got slower, or the server's output
  while the client uploads, keeps its window. The interactive class also
  keeps two segments of its own in flight whatever the bulk class holds, so
  a keystroke never waits for bulk data to drain. A retransmit timeout
  whose segment is acknowledged sooner than a round trip after the resend
  was only a late ACK, and is undone -- window, thresholds, back-off, and
  nothing sent again; and output that goes past the window on the
  interactive allowance grows the window, so a terminal session a timeout
  left at one segment grows back.
- **Control before data, and no stream in front of the others.** A timer's
  PING and road checks go out before the data it flushes, and streams share
  a flush round-robin instead of in stream-number order (`UPDATE_STREAM`, 14,
  used to go out entirely before any channel, 16 and up).
- **Automatic moving has a second trigger, and forces a PING on every move.**
  This changes roaming for every multipath session. Besides `PathDown` (no
  ordinary frame for `PATH_DOWN_AFTER`), a client now also leaves the road in
  use when that road failed its own check while the PINGs down it go
  unanswered -- and only when the two overlap in time: the PINGs were found
  unanswered no later than the failed check was sent. This catches a road
  that died while the server keeps talking over the road left, which never
  goes quiet. A road in use that reads `Dead` makes the checks urgent, so a
  single lost check is re-checked within `PROBE_URGENT` (1 s) and heals one
  round trip later instead of standing for half a minute. Every automatic
  move, like a move by hand, forgets the PINGs sent down the road left and
  forces a PING down the new one, so the server follows after one packet and
  the client does not bounce back onto the road it left.
- **PINGs work on roads slower than `PING_INTERVAL`.** Up to four
  outstanding PINGs are remembered and a PONG for any of them counts, so the
  round trip is measured on a road slower than the interval (up to about
  6 s); a PING counts as unanswered only once it is older than both the
  interval and the retransmit timeout, so such a road no longer reads as
  failing for good -- as long as its round trip stays under the retransmit
  timeout's 3 s cap. A road slower than that still reads its PINGs as
  unanswered. A road up to about 3 s is kept next to a fast verified spare
  as long as both ends run this version; a daemon older than this still
  drops the client's slow-road packets that the spare's checks overtake.

- **Names and targets in tmux commands are sent as typed.** A session or
  window name (`new_session`, `rename_session`, `rename_window`) has every
  control character turned into a space and is trimmed -- nothing is sent
  if nothing is left -- and on tmux 2.7+ its `#` is doubled, so tmux does
  not expand `#S` or `#(cmd)` in it. A session addressed by name is
  matched exactly (`=name`, tmux 2.1+); `$id` targets are unchanged. Any
  other command with a control character in it is not sent.
- **Trees reach the platform in order.** A tree snapshot taken earlier but
  delivered later (two threads at once) is dropped.

- **tmux trouble no longer ends a hybrid session.** The control channel
  (`tmux -C`) ending once the attach has been typed is reported through the
  new `TmuxEvents::on_control_channel(false, reason)`, and the shell goes on;
  `TmuxSession::reopen_control` opens a fresh control channel in the same
  session, reported up once tmux answers on it. tmux commands are not built
  while there is no control channel. A tmux that cannot be started at all
  is reported as the new readiness `Unavailable` instead of closing the
  session.
- **`qshd` has a `test-build-labels` feature** for measurements with an
  optimized binary; release builds without it ignore
  `QSHD_TEST_BUILD_LABELS`, as before.

### Fixed

- **`qsh` (console) no longer queues without a limit.** Its channels'
  bytes count as taken when they reach the terminal: with a daemon of this
  version a slow terminal holds back only its own channel, a window at
  most; with an older daemon the client waits once 1 MiB waits for the
  terminal, instead of growing its memory for as long as output comes.
  `StdClient::connect_with` takes a `DriverSetup` (how streams count their
  consumption, in force before the first datagram) and
  `StdClient::consumed` reports; `ClientEvents::on_features` says what
  the handshake agreed.
- **A slow consumer no longer stops the daemon's session bridge.** The
  bridge waited for its backend to take every delivered chunk; a handler
  that stopped reading stopped the whole session -- no PONG, no ACK, no
  timer, no other channel. Now what the backend has no room for waits in
  the bridge, bounded per stream by its credit window and per session by
  8 MiB, and the bridge goes on; only past 8 MiB does it wait for the
  backend, as before. An honest client never gets there; a client without
  credits is queued up to the same 8 MiB. On a graceful end what waits
  still reaches the backend, in order.
- **Big output no longer piles up in the daemon.** `cat` of a large file in
  a channel used to queue everything in the daemon's memory in front of the
  client. A channel with a screen model now drops output its gate holds
  back and repaints once the client has caught up (Ctrl-C shows within a
  fraction of a second); a `tmux -C` channel makes its process wait instead.

- **A repaint restores the terminal, not only the screen.** The daemon's
  repaint (now `TerminalCore::replay`, on a core made
  `TerminalCore::with_replay`; one made with `new` runs as before) left the client with the full-screen
  scroll region, the last painted cell's colours as its pen, whatever
  character set it had, and the parser outside any sequence -- so after a
  repaint tmux's next linefeed scrolled the whole screen instead of its
  pane, its text came out in the status line's colours, and line drawing
  cut in the middle turned letters into box glyphs. It now restores the
  scroll region, the pen, the character sets and the active one, every
  input and wrap mode, the pending wrap at the last column, the saved
  cursor, the tab stops, the palette, the cursor style, the last printed
  character and the unfinished escape sequence the output stopped in, and
  on the alternate screen the primary screen underneath as well. On the
  primary screen it rewrites the rows in place instead of clearing the
  screen, so the client's scrollback no longer gets a copy of the screen
  with every repaint.
- **A channel's exit no longer overtakes its last output.** `EXIT` went out
  on the control stream as soon as the process ended, overtook the
  channel's stream, and the client dropped whatever of the channel came
  after it -- the end of a command's output, or the last frame of a screen
  channel whose output was being dropped. The daemon now repaints such a
  channel before it goes and sends `EXIT` once the channel's output is
  acknowledged (`SessionIo::notify_delivered`, `SessionInbound::Delivered`).

- **An acknowledgement no longer moves the whole send backlog.** The stream
  sender kept its unacknowledged bytes in a `Vec` and cut every ACK's bytes
  off the front, moving everything behind them: 32 MiB queued at once took
  52 s to go through in memory, 8 KiB chunks 0.25 s. The buffer is a ring now
  (`VecDeque`): what an ACK costs no longer grows with the backlog behind it,
  and 32 MiB at once goes through in 0.33 s. A ring that a burst grew past
  1 MiB gives that memory back as it drains, instead of holding its peak for
  the rest of the connection.

- **The first PING goes out even while the server streams output.** It was
  scheduled `PING_INTERVAL` after the last packet received, so a server
  sending output more often than every 1.5 s from the handshake on (a clock
  in tmux, `htop` after a reconnect) held it off for the whole session: no
  round trip was measured and the unanswered-PING evidence the multipath
  rules read never existed. It is now scheduled from the handshake.
- **Retransmits fall due `rto` after the segment went out, and an ACK refills
  the window at once.** The retransmit wake-up was `rto` after the last
  datagram of any kind, so a side busy acknowledging an inbound flow kept
  pushing its own retransmit back until the next PING. It is now the oldest
  unacknowledged segment's last send plus `rto`. An ACK that moves a sender's
  base forward sends the next bytes of the window in the same call instead of
  waiting for a timer.
- **Timers run while datagrams keep arriving.** The client driver ran
  `Connection::on_timeout` only when a read timed out, so a server sending
  more often than every 50 ms stopped the client's PINGs, retransmits,
  `PathDown`, road checks, the dead-road rule and the msg1 retransmit. Every
  loop around a `Connection` -- the client driver, the daemon's bridge,
  probation, `serve_shell`, `serve_echo` -- now runs the timers that are due
  after every wake-up (`Connection::on_timeout_if_due`). The client driver
  also takes in up to 64 datagrams already waiting before it runs timers and
  hands out events. And the next PING's deadline now agrees with
  `on_timeout` across the 60 s backoff boundary, where it used to stay due for
  up to 13.5 s.
- **What was written while the path was down goes out on return.** `send`
  queues without sending outside `Live`, and only the server's resync flushed
  on the way back to `Live`, so a keystroke typed during `PathDown` waited for
  the client's next timer, up to a PING interval. The packet that ends
  `PathDown` now flushes every sender on both sides, and output queued but
  never sent while `Live` is due at once in `Connection::next_timeout`.
- **The round trip is either measured or not, never 0 for both.** A round
  trip under 1 ms was stored as 0 and read as "not measured", so loopback and
  fast LANs kept the 500 ms default retransmit timeout for good. It is now
  kept at full precision; `Stats::rtt_ms` shows at least 1 once anything is
  measured. A client seeds it from its handshake (msg1 to msg2) unless msg1
  was retransmitted, so the header shows a round trip right after
  connecting. Until the first measurement a PING counts as unanswered only
  after the 3 s retransmit-timeout ceiling, so a road with a round trip
  between 1.5 s and 3 s is no longer called unanswered on its first PING.
  New: `Connection::rtt`, `Connection::retransmit_handshake` (the driver's
  msg1 retransmit, counted for Karn's rule), `RttSample`, `RttSource`.
- **The retransmit timer measures the queue it sends into.** A bulk write
  on a slow uplink (the daemon update right after connecting, or any later
  one) waits seconds in the uplink's queue, while the timeout came from a
  PING round trip taken on an idle road: 200 ms under a 2 s queue resent the
  whole window every 200 ms, and on a deep queue the PONG came back after its
  PING had been forgotten, so the upload never finished. The timer now keeps
  an RFC 6298 estimate (SRTT, RTTVAR) fed by every PONG and by every data
  segment acknowledged without having been retransmitted (Karn's rule):
  `SRTT + max(4 * RTTVAR, SRTT / 4)` within [200 ms, 15 s]. Each expiry
  doubles it until a new sample or a return from `PathDown`. The handshake
  seed may raise it above the 500 ms default but never lower it. Road
  liveness (unanswered PINGs, the move dwell) and `Stats::rtt_ms` keep the
  latest PONG, within the 3 s ceiling. A freeze of the thread (Doze), a
  rebind and a road move forget the send times of the data in flight, as
  they forget the outstanding PINGs, and drop the back-off; a move also
  starts the estimate afresh. Simulator, 8 MiB up, when the bottleneck queue
  holds the 256 KiB window: 125 KB/s 83 % goodput and 89 % resent before,
  96 % and 0 % after; 64 KB/s, and a write 10 s into an idle session over a
  1 MiB queue, did not finish in ten minutes, now 96 % and 0 %. With a queue
  smaller than the window the transfer degrades until slice 2's congestion
  response: tail drops are real losses, repaired by timeout alone, and the
  resends refill the same queue -- 125 KB/s over a 64 KiB queue takes 115 s
  (59 %), and 64 KB/s over a 64 KiB queue crawls, about 860 s for 8 MiB
  (it took 305-414 s before this change).
- **The replay window holds 32 704 positions.** It held 64, and the counter
  is one per direction for all roads, so a fast spare's check answers
  overtaking more than 64 packets on a slow road in use made those packets --
  PONGs and check answers among them -- read as too old. It is now an
  RFC 6479 bitmap of 32 768 bits (4 KiB per connection). Each side fixes its
  own receive direction.
- **Nothing a client sends during probation is lost.** Datagrams that
  arrived while the daemon verified a signature -- and after, until the
  session was bound -- were dropped with the probation task; a road check
  among them went unanswered for 30 s. The queue now goes to the bridge with
  the connection: a fresh session adopts it as its own route, a warm
  reattach hands it over inside the `Attach`.
- **A stream stops at the end of its 32-bit offset space instead of
  overflowing.** A sender refuses bytes past `u32::MAX` − 16 MiB
  (`reliability::OFFSET_LIMIT`; `StreamSender::push` now returns a
  `Result`) and the connection reports the new
  `Event::OffsetSpaceExhausted` once per stream. Whichever side hit it
  drops the connection without a `Close` (`Connection::abandon`; the
  daemon's bridge and `qshd transport-shell` alike), so the daemon keeps the
  session and its processes. The console `qsh`
  exits -- at once when its own stream hit the limit, after its 2 h death
  timer when the daemon's did -- and prints that the session is kept; its
  next run to the same host and port returns to it. The owner of a
  `StdClient` can tell a `Close` from a death with the new
  `StdClient::closed_gracefully`. A receiver drops a `DATA` frame that ends
  past `u32::MAX`. Between two ends of this version modular offsets
  (`offset-wrap`, see Added) remove the edge; it stays with a peer built
  before them.

### Security

- **One datagram draws one answer.** Answers were built frame by frame, so
  a peer -- one still in probation included -- could pack a datagram with
  PINGs, road checks or empty DATA frames and draw a datagram for each:
  270 PONGs for one 1 384-byte datagram of 270 PINGs, sent wherever its
  forged source pointed. Now a datagram draws one PONG (for its last
  PING, with at most one CREDIT copy), one ACK and at most one CREDIT per
  stream, packed together, and one road-check answer, alone, to its
  source.
- **A receiver holds a bounded amount of out-of-order data** (QSH-01).
  Before, a peer that had only finished a Noise handshake -- on the
  signature path with a throwaway key -- could make a receiver buffer
  data past a hole without limit and run the daemon out of memory. Now a
  stream keeps nothing past the window its sender may use (256 KiB past
  its point for a sender without credits) and at most one window of cost,
  a chunk costing its bytes plus 128 (what its place in the map was
  measured to take, however a peer orders its chunks); a connection keeps
  at most 8 MiB on all its streams, 64 KiB while in probation. What does
  not fit is dropped unacknowledged and sent again; honest senders never
  get there. A `Reset` costs about the chunks it drops, not every chunk
  the stream holds (a flood of small ones was a CPU lever).
- **A PING draws at most a PONG and one `CREDIT`, and a server takes no
  `Reset` from a client.** Found before release in this version's credits:
  a `Reset` on each stream number, from a peer still in probation, made
  every later PING draw one `CREDIT` datagram per stream -- 257 datagrams
  for a 39-byte PING, sent wherever the peer's forged source pointed. Now a
  server drops a client's `Reset` whole (no build sends one), and a PONG
  carries one `CREDIT` copy at most, the streams taking it in turn.
- **A session's datagram route is bounded** (QSH-04): at most 1 MiB queued
  between the socket loop and a bridge, each datagram costing its length
  plus 64, and 128 KiB while the connection is in probation (raised to
  1 MiB when it is proven); past that datagrams are dropped, as the network
  would. Before, a bridge that waited on its backend let its route grow
  without limit.
- **The datagram header is authenticated between two new ends.** When both
  sides of a connection are this version they negotiate `header-aad` in the
  handshake, and the 18 bytes of every transport datagram's header (version,
  kind, session id, counter) become the AEAD's associated data. With an older
  client or daemon the header stays outside it, as before: the counter is
  still the nonce, the session id is not authenticated. A server that enables
  what the client did not offer is refused: the client closes and says so.
- **A handshake must prove its return address when the daemon is under
  load.** Every `HandshakeInit` used to cost Noise's X25519 work and, on the
  signature path, a probation seat before anything proved its sender
  received at its address: eight forged addresses could fill the probation
  table and lock every sign-in and warm reattach out, and a flood kept a
  core busy. Now, while more than 64 handshakes arrive a second or more than
  half the table is taken, a msg1 draws only a 35-byte cookie reply (a
  BLAKE2s MAC over the sender's address, port and ephemeral key, under a
  secret replaced every two minutes); only the same msg1 sent again behind a
  valid cookie is worked on, and no more than 20 a second from one address
  after a burst of 5 (WireGuard's rate limit), since a cookie proves an
  address, not a datagram. New clients answer cookies and pay one round
  trip, and only under load; clients built before this are refused while
  the load lasts. The daemon logs when load starts, and when it has stayed
  off for 10 seconds. Once a new client has taken a cookie, its msg1
  retransmits alternate between the cookie and the plain msg1, so a cookie
  forged by a party on the path cannot keep it out of a daemon built before
  this, which drops a msg1 behind a cookie.
- **A record's declared length is bounded** (QSH-06): 64 KiB on the
  session-control stream, 64 MiB elsewhere; a longer one stops that
  stream's reader instead of growing its buffer for as long as bytes come.
  A warm reattach starts the daemon's control reader afresh, so a record
  the old connection cut short no longer splices onto the new one.
- **The control socket is owner-only from its first instant** (QSH-14):
  bound in a private directory and moved into place, instead of bound
  under the umask and tightened afterwards. A daemon that died between
  the two leaves that directory behind (`.c<pid>`, empty or holding a dead
  socket); the next daemon to start removes it -- only its own uid's, only
  `0700`, only one unchanged for a minute whose pid no process has, never
  through a symlink, and only if it holds nothing but that socket.

## [0.2.0] — 2026-09-24

Still pre-1.0: interfaces may change between minor versions.

### Added

- **The daemon updates itself through qsh** — a client offers a newer
  `qshd` over the authenticated session (`About`, `UpdateOffer`, a dedicated
  update stream); the daemon checks size, checksum and `qshd self-check`,
  refuses while other sessions are active, and replaces itself with `exec`
  keeping its PID, port, server key and client keys (`transport-resume`).
  A packaged (`--system` or `serve`) daemon never accepts an image.
- **SSH sessions in the core** (`crates/ssh`, russh) — the same terminal
  over SSH: host keys checked by the caller, password or
  external-signer login, keepalive, knock before connect.
- **Port knocking in the core** (`crates/knock`) — knock sequences run by the
  core before connecting.
- **Direct login by signature** — a client logs in to the daemon with an SSH
  key signature; SSH is only needed to install the daemon.
- **System mode** (`qshd serve --system`) — sessions belong to accounts; a
  privileged helper and an unprivileged worker; PAM; deb and rpm packages
  with systemd units.

### Fixed

- The `tmux attach` the client sends is kept out of the shell history.

## [0.1.0] — 2026-09-09

First tagged version. The pieces below have been in daily use against real
servers, but none of the interfaces are settled yet: while the major version
is 0, a minor bump may break them.

### Added

- **Roaming transport** (`crates/transport`) — an encrypted UDP transport
  (Noise) that keeps a session alive across a change of address: a phone
  moving between Wi-Fi and mobile data continues in place, with no reconnect
  and no lost input. Several paths to the same daemon can be probed and used.
- **Terminal model** (`crates/terminal`, `crates/render`) — a VT screen built
  on `alacritty_terminal`, and rendering of frame differences back into
  control sequences.
- **Input prediction** (`crates/prediction`) — keystrokes appear locally
  before the server confirms them, in the manner of mosh, with the same
  epoch-based confirmation.
- **tmux control mode** (`crates/tmux`) — parsing of the control-mode
  protocol: sessions, windows, panes, and the notifications that change them.
- **The daemon** (`qshd`) — hands out channels to whoever proves their
  identity with an SSH key signature. It either runs as a standing service
  (`qshd serve`) or is installed over SSH by a client and keeps itself up to
  date; both are described in `docs/qshd-service.md`.
- **Console client** (`cli`) — the `qsh` command: connects, authenticates by
  SSH key, and hosts a shell over the roaming transport.
- **Foreign-language bindings** (`crates/ffi`) — UniFFI bindings for embedding
  the shared core in other hosts.
