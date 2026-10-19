//! Async interactive-shell server on top of the sans-IO `Connection` core: a
//! "blocking PTY <-> reliable transport" bridge for A SINGLE client.
//!
//! The shape of the server loop matches [`crate::driver_tokio::serve_echo`]
//! (select recv/timeout, sending outgoing datagrams, dispatching `poll_events`),
//! with replacement connections admitted before switching. Two more wakeup
//! sources are added -- PTY output and the `echo_ack` flush timer -- along
//! with handling of the incoming streams:
//! - stream `STREAM_IO` (0) -- bidirectional shell I/O: incoming bytes are
//!   written to the PTY as-is; PTY output goes to the client on the same
//!   stream, but framed ([`crate::shell_frame`]) as a DATA record,
//!   immediately followed by an ECHO_ACK record with the offset of input
//!   consumed by the server (plus a flush of ECHO_ACK on a short timer if
//!   input has advanced but no output happened -- the program silently ate
//!   a keystroke);
//! - stream `STREAM_CONTROL` (1) -- control records for resize (see
//!   [`apply_resize_records`]).
//!
//! **PTY isn't here.** The transport crate does NOT know about
//! `portable-pty` (that would be a circular dependency with qshd, which
//! already depends on transport). So the PTY is spun up by the caller (the
//! `transport-shell` subcommand in qshd), which hands over an already-ready
//! reader/writer pair for the PTY master side plus a resize handle
//! ([`ResizeHandle`]). This keeps the transport clean, while PTY knowledge
//! stays on the server side.
//!
//! **The "blocking PTY <-> async" bridge.** PTY I/O (`Read`/`Write`) is
//! synchronous and blocking, while the loop is async. Each direction gets a
//! blocking task (`tokio::task::spawn_blocking`), which talks to the loop
//! via `tokio::sync::mpsc`: the PTY reader sends chunks into `pty_out` (a
//! bounded channel -- backpressure throttles shell reads if the network
//! can't keep up), and the loop forwards them into `conn.send(STREAM_IO,
//! ...)`; the PTY writer pulls chunks from `pty_in`, where the loop puts
//! incoming bytes of stream 0. Resize is a quick ioctl, called directly from
//! the loop (as in qsh's `session.rs`).
//!
//! **PTY input is an UNbounded channel.** Sending into `pty_in` from the
//! loop is synchronous and never blocks it. A bounded channel would be
//! dangerous: a chatty command that doesn't read stdin (e.g. `yes`) wouldn't
//! drain `pty_in`, it would fill up, and `send().await` would freeze the
//! ENTIRE event loop -- timers/keepalive and `pty_out` draining would stall,
//! and the connection would time out on liveness. Terminal input is small
//! (keystrokes/paste), so the memory-growth risk is negligible -- a
//! deliberate tradeoff in favor of a non-blocking loop.
//!
//! **Roaming vs. a new client.** Address migration (roaming) does NOT create
//! a new handshake -- the core migrates to the new source on its own within
//! the same `Connection`, and the shell keeps running. A new `HandshakeInit`
//! from a different or restarted client replaces the `Connection` only after
//! the Noise and allowlist checks and fresh transport proof admit it. A rejected or incomplete
//! candidate leaves the active connection and its control/echo state intact.
//! An admitted replacement does not touch the shell or PTY: it reconnects to
//! the same live shell, with fresh control and echo accounting.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Instant;
use terminal_size::TerminalSize;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::conn::{Connection, ConnectionConfig, Datagram, Event, LinkState};
use crate::raw_admission::{PacketResult, PendingAdmission};
use crate::shell_frame::{encode_record, REC_DATA, REC_ECHO_ACK};

/// Receive buffer size for a single UDP datagram.
const RECV_BUF_LEN: usize = 64 * 1024;

/// Buffer size for a single PTY read.
const CHUNK_SIZE: usize = 8 * 1024;

/// Capacity of the bounded PTY output channel (`pty_out`) -- small: the
/// channel isn't a data buffer, it's a decoupling point between execution
/// threads (the bottleneck is the byte transfer itself, not queue depth).
/// Backpressure here is desirable -- it throttles shell reads if the network
/// can't keep up. The INPUT channel (`pty_in`) is UNbounded (see the module
/// docs): pressure there is unacceptable.
const CHANNEL_CAPACITY: usize = 16;

/// The bidirectional shell I/O stream.
const STREAM_IO: u8 = 0;

/// The control-record stream (resize).
const STREAM_CONTROL: u8 = 1;

/// A PTY resize handle. The transport crate does NOT know about
/// `portable-pty` (that would be a circular dependency with qshd), so resize
/// is abstracted behind a trait: the PTY is spun up in qshd, and an
/// already-ready handle is passed in here. qshd provides the implementation
/// over the PTY master side.
pub trait ResizeHandle: Send {
    /// Resize the terminal to `cols` columns by `rows` rows.
    fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String>;
}

/// Preparation failed before any PTY or model mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenPreparationError {
    ResourceLimit(String),
    PreparationFailed(String),
}

impl std::fmt::Display for ScreenPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourceLimit(detail) | Self::PreparationFailed(detail) => f.write_str(detail),
        }
    }
}

/// A model resize reserved before PTY ioctl; cancellation leaves it unchanged.
pub trait PreparedScreenResize: Send {
    fn commit(self: Box<Self>);
}

struct EmptyResize;
impl PreparedScreenResize for EmptyResize {
    fn commit(self: Box<Self>) {}
}

/// The session's own model of what is on the screen.
///
/// The transport does not know what a terminal is -- exactly as it does not
/// know what a PTY is (see the module header). It only knows that somebody
/// upstream can absorb the shell's output, follow the size, and, when asked,
/// produce the bytes that reconstruct the current screen from scratch. The
/// implementation lives in `qshd` (`qshd/src/screen.rs`), which owns the
/// emulator and the renderer.
///
/// The bytes `repaint` returns are consumed by the CLIENT's emulator, not by
/// a real terminal: they may use everything our own emulator understands.
pub trait SessionScreen: Send {
    /// Feed the shell's output through the model. Called for every chunk,
    /// with exactly the bytes that also go on the wire.
    fn absorb(&mut self, bytes: &[u8]);

    /// Reserve model storage before touching the PTY. Drop cancels; commit
    /// applies the model only after the PTY accepted the same geometry.
    fn prepare_resize(
        &mut self,
        size: TerminalSize,
    ) -> Result<Box<dyn PreparedScreenResize + '_>, ScreenPreparationError>;

    /// Bytes that rebuild the current screen from scratch: content, cursor
    /// and modes. An empty answer means "nothing to say" and puts nothing on
    /// the wire.
    fn repaint(&mut self) -> Vec<u8>;

    /// Whether this model actually has something to redraw from -- `true`
    /// by default, overridden by [`NoScreen`] to `false`.
    ///
    /// This is what `channel_server.rs`'s `open_channel` asks to decide a
    /// channel's recoverability, NOT the request's own `OpenRequest::screen`
    /// bit: a caller can ask for a screen and still get `NoScreen` back --
    /// `qshd/src/channel_backend.rs`'s `make_screen` hands back `NoScreen`
    /// for any request that didn't ask for one (`req.screen == false`), and a
    /// future backend with no emulator of its own to build a real model from
    /// could hand back `NoScreen` regardless of what was asked. Declaring
    /// recoverable off `req.screen` instead would tell the connection there
    /// is something to repaint from when there is not: after a long absence
    /// the backlog gets dropped, the resync asks this exact model to
    /// repaint, and an empty answer leaves the client desynced with no way
    /// back. Asking the model itself is the only way to get the true answer.
    fn has_screen(&self) -> bool {
        true
    }
}

/// A screen that models nothing: `repaint` answers "nothing to say", so the
/// runner puts nothing on the wire. For tests that are not about the screen,
/// and for any request that didn't ask for one (`req.screen == false`) or any
/// backend that gets its repaint from somewhere else.
pub struct NoScreen;

impl SessionScreen for NoScreen {
    fn absorb(&mut self, _bytes: &[u8]) {}
    fn prepare_resize(
        &mut self,
        _size: TerminalSize,
    ) -> Result<Box<dyn PreparedScreenResize + '_>, ScreenPreparationError> {
        Ok(Box::new(EmptyResize))
    }
    fn repaint(&mut self) -> Vec<u8> {
        Vec::new()
    }
    fn has_screen(&self) -> bool {
        false
    }
}

/// What woke up the loop: a packet arrived (or a receive error), a core
/// timer fired, the PTY produced output (`None` means the PTY reader
/// finished, i.e. the shell exited), or the short `echo_ack` flush timer
/// fired.
enum Wakeup {
    Packet(std::io::Result<(usize, SocketAddr)>),
    Timeout,
    PtyOut(Option<Vec<u8>>),
    AckTick,
}

fn legacy_shell_config(mut cfg: ConnectionConfig) -> ConnectionConfig {
    cfg.features =
        crate::Features::from_bits(cfg.features.bits() & !crate::Features::CHANNEL_GEOMETRY.bits());
    cfg
}

/// Serve a single interactive shell on socket `socket` with config `cfg`
/// (role must be server). The PTY is already spun up by the caller and
/// handed over here as a reader/writer pair for its master side, plus a
/// resize handle.
///
/// The function returns only once the shell has exited (EOF on the PTY
/// read); until then it runs the receive/send loop and the PTY bridge.
///
/// **No screen model here, on purpose.** The multi-session path
/// (`crate::channel_server::run_channel_session`) gives every channel a
/// [`SessionScreen`] and repaints from it after a long absence; this
/// single-client entry point does not, and the two runners differ in exactly
/// that. Screen-model repaint is scoped to the multi-session path, which is
/// what `qshd serve` actually runs -- `serve_shell` is the older one-shot
/// path and was left as it was rather than grown a second copy of the
/// wiring.
///
/// **Stream 0 means something different here than in the channel protocol.**
/// This is the pre-channels protocol: it fixes one shell up front, so
/// `STREAM_IO` (0) carries that shell's own input and output for the whole
/// connection -- the same number `crate::conn::OUTPUT_STREAM` names, so its
/// backlog is dropped after a long absence and a repaint replaces it
/// (exactly what this file's own resync tests exercise). The channel
/// protocol (`crate::channel_server`) uses `CONTROL_STREAM` (1, deliberately
/// NOT 0 -- see that constant's own doc) for open/close/resize requests for
/// however many channels the client asks for, and gives each channel's
/// actual data a stream number of its own starting at `FIRST_CHANNEL_STREAM`
/// (16). The two protocols never share a connection, so the two layouts
/// never collide in practice, but a reader jumping between the two files
/// must not carry one file's stream numbering into the other.
pub async fn serve_shell(
    socket: UdpSocket,
    cfg: ConnectionConfig,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    resize: Box<dyn ResizeHandle>,
) {
    let cfg = legacy_shell_config(cfg);
    // The PTY bridge: two blocking tasks + two channels. The PTY reader puts
    // chunks into `pty_out`, the PTY writer pulls chunks from `pty_in`.
    let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    // `pty_in` is UNbounded: a synchronous send from the loop never blocks
    // it, even if the PTY writer has stalled (see the module docs).
    let (pty_in_tx, pty_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let _reader_task = tokio::task::spawn_blocking(move || pty_to_channel(reader, pty_out_tx));
    let _writer_task = tokio::task::spawn_blocking(move || channel_to_pty(pty_in_rx, writer));

    let mut buf = vec![0u8; RECV_BUF_LEN];
    // A single connection. `None` until the first admitted handshake and
    // after the session closes (ready for a new client).
    let mut conn: Option<Connection> = None;
    let mut pending = PendingAdmission::default();
    // Buffer for unfinished control records on stream 1 (a reliable stream
    // can deliver a 5-byte record split across fragments or merged).
    let mut control_buf: Vec<u8> = Vec::new();

    // How many input bytes have been consumed into the PTY (for echo_ack)
    // and the last value sent (so we don't send unchanged values).
    let mut input_consumed: u64 = 0;
    let mut last_acked: u64 = 0;
    // Short echo_ack flush timer: if input advanced but there was no output
    // (the program silently ate a keystroke), the acknowledgment still goes
    // out.
    let mut ack_tick = tokio::time::interval(std::time::Duration::from_millis(20));
    ack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // The nearest timer of the current connection (if any).
        let next = conn
            .as_ref()
            .and_then(Connection::next_timeout)
            .into_iter()
            .chain(pending.next_timeout())
            .min();

        let wakeup = match next {
            Some(deadline) => {
                let dur = deadline.saturating_duration_since(Instant::now());
                tokio::select! {
                    r = socket.recv_from(&mut buf) => Wakeup::Packet(r),
                    _ = tokio::time::sleep(dur) => Wakeup::Timeout,
                    c = pty_out_rx.recv() => Wakeup::PtyOut(c),
                    _ = ack_tick.tick() => Wakeup::AckTick,
                }
            }
            // No timers (no session, or it's closed) -- wait for a packet or
            // PTY output.
            None => {
                tokio::select! {
                    r = socket.recv_from(&mut buf) => Wakeup::Packet(r),
                    c = pty_out_rx.recv() => Wakeup::PtyOut(c),
                    _ = ack_tick.tick() => Wakeup::AckTick,
                }
            }
        };

        let now = Instant::now();
        let mut out: Vec<Datagram> = Vec::new();
        let mut admitted_events = Vec::new();

        match wakeup {
            Wakeup::Packet(Ok((len, src))) => {
                match pending.on_packet(&cfg, now, src, &buf[..len], &mut out) {
                    PacketResult::Admitted(admitted) => {
                        let admitted = *admitted;
                        conn = Some(admitted.conn);
                        admitted_events = admitted.events;
                        control_buf.clear();
                        input_consumed = 0;
                        last_acked = 0;
                    }
                    PacketResult::Handled => {}
                    PacketResult::Unrelated => {
                        if let Some(c) = conn.as_mut() {
                            out.extend(c.on_datagram(now, src, &buf[..len]));
                        }
                    }
                }
            }
            // Receive error -- nothing to process, the socket is still alive.
            // No `continue`: the timers below run after this wake-up too.
            Wakeup::Packet(Err(_)) => {}
            // Nothing of its own: the timers run after every wake-up, below.
            Wakeup::Timeout => {}
            Wakeup::PtyOut(Some(chunk)) => {
                // Shell output goes to the client as a framed DATA record on
                // stream 0, immediately followed by an ECHO_ACK with the
                // current offset of consumed input: the acknowledgment
                // travels on the same reliable ordered stream right after
                // its own output, so the client applies it only after
                // feeding the output to the emulator. If there's no client
                // yet (conn=None), the output is dropped -- there's no
                // screen buffer at this layer (that's the job of the
                // terminal emulator on the client side). conn.send itself
                // queues bytes while the session isn't Live, and flushes
                // them on the transition.
                if let Some(c) = conn.as_mut() {
                    out.extend(c.send(now, STREAM_IO, &encode_record(REC_DATA, &chunk)));
                    out.extend(c.send(
                        now,
                        STREAM_IO,
                        &encode_record(REC_ECHO_ACK, &input_consumed.to_be_bytes()),
                    ));
                    last_acked = input_consumed;
                }
            }
            Wakeup::PtyOut(None) => {
                // The PTY reader finished -- the shell exited. Wind down.
                break;
            }
            Wakeup::AckTick => {
                // Flush echo_ack on the short timer: input advanced but no
                // PTY output happened (the program silently ate a
                // keystroke, e.g. a password prompt or a control sequence)
                // -- the acknowledgment must still reach the client.
                if let Some(c) = conn.as_mut() {
                    if input_consumed != last_acked {
                        out.extend(c.send(
                            now,
                            STREAM_IO,
                            &encode_record(REC_ECHO_ACK, &input_consumed.to_be_bytes()),
                        ));
                        last_acked = input_consumed;
                    }
                }
            }
        }

        pending.on_timeout(now, &mut out);
        // Timers after every wake-up (spec §4.1).
        if let Some(c) = conn.as_mut() {
            out.extend(c.on_timeout_if_due(now));
        }
        send_all(&socket, &out).await;

        // Core events: bytes delivered on stream 0 are written to the PTY,
        // records on stream 1 are applied as resize, session close resets
        // conn.
        let reset = match conn.as_mut() {
            Some(c) => apply_event_batch(
                c,
                admitted_events,
                &mut input_consumed,
                &pty_in_tx,
                &mut control_buf,
                resize.as_ref(),
            ),
            None => false,
        };
        if reset {
            conn = None;
            control_buf.clear();
        }
    }

    // The shell exited (EOF on the PTY read gave `PtyOut(None)` -- the PTY
    // reader has already returned). Close the input channel: the PTY writer
    // will get `None` on receive and exit on its own. It's the channel
    // closing that stops it -- `JoinHandle::abort()` doesn't interrupt an
    // already-running `spawn_blocking` thread, so we rely on closing the
    // channel rather than on abort. The wrapper tasks detach on function
    // exit.
    drop(pty_in_tx);
}

/// Applies the connection's events to the shell: bytes on stream 0 go to the
/// PTY (counted into `input_consumed` first), records on stream 1 resize it.
/// Returns whether the session ended, so the loop drops the connection and
/// waits for the next client -- the shell itself lives on.
///
/// A stream out of offset space ends the session too (spec §4.14): the
/// connection is abandoned without a `Close`, as the daemon's bridge does,
/// instead of staying `Live` with an output stream that refuses every write.
/// The client's next connection starts its streams at 0.
#[cfg(test)]
fn apply_events(
    c: &mut Connection,
    input_consumed: &mut u64,
    pty_in_tx: &mpsc::UnboundedSender<Vec<u8>>,
    control_buf: &mut Vec<u8>,
    resize: &dyn ResizeHandle,
) -> bool {
    apply_event_batch(
        c,
        Vec::new(),
        input_consumed,
        pty_in_tx,
        control_buf,
        resize,
    )
}

fn apply_event_batch(
    c: &mut Connection,
    mut events: Vec<Event>,
    input_consumed: &mut u64,
    pty_in_tx: &mpsc::UnboundedSender<Vec<u8>>,
    control_buf: &mut Vec<u8>,
    resize: &dyn ResizeHandle,
) -> bool {
    events.extend(c.poll_events());
    let mut ended = false;
    for ev in events {
        match ev {
            Event::StreamData { stream_id, data } => match stream_id {
                STREAM_IO => {
                    // The offset of consumed input grows BEFORE sending to the
                    // PTY: this exact number goes into the next echo_ack (the
                    // server has already accepted these bytes, not merely
                    // handed them to the writer).
                    *input_consumed += data.len() as u64;
                    // Feed into the PTY. The send is synchronous (unbounded
                    // channel) and does NOT block the loop; the writer task
                    // drains the channel. Err only if the writer has gone
                    // away (the shell is dead) -- a clean exit will follow
                    // via PtyOut(None).
                    let _ = pty_in_tx.send(data);
                }
                STREAM_CONTROL => {
                    control_buf.extend_from_slice(&data);
                    // `serve_shell` has no screen model to feed (see
                    // `run_channel_session` in `channel_server.rs` for that
                    // wiring) -- the applied size is beside the point here.
                    let _ = apply_resize_records(control_buf, resize);
                }
                // Other streams are unused by this protocol.
                _ => {}
            },
            Event::StateChanged(LinkState::Closed) => ended = true,
            Event::OffsetSpaceExhausted { .. } => {
                c.abandon();
                ended = true;
            }
            _ => {}
        }
    }
    ended
}

/// Parses accumulated control records for stream 1 out of the buffer and
/// applies resize. Record format (must match the client byte-for-byte):
/// `type(1)=0x01(resize) | cols(u16 BE) | rows(u16 BE)` = 5 bytes. A
/// reliable stream can deliver records fragmented or merged, so we
/// accumulate bytes and read out exactly 5 at a time. An unknown first byte
/// means a protocol desync: shift by one byte and try again.
///
/// Returns the LAST size applied, or `None` if the buffer held no complete
/// record. A batch of coalesced records is a drag in progress: only the size
/// it ended on matters to anyone downstream.
fn apply_resize_records(buf: &mut Vec<u8>, resize: &dyn ResizeHandle) -> Option<(u16, u16)> {
    /// The resize record type.
    const RESIZE: u8 = 0x01;
    /// Length of a single resize record in bytes.
    const RECORD_LEN: usize = 5;

    let mut consumed = 0;
    let mut applied = None;
    while buf.len() - consumed >= RECORD_LEN {
        if buf[consumed] != RESIZE {
            // Unknown type -- shift by a byte to resynchronize.
            consumed += 1;
            continue;
        }
        let cols = u16::from_be_bytes([buf[consumed + 1], buf[consumed + 2]]);
        let rows = u16::from_be_bytes([buf[consumed + 3], buf[consumed + 4]]);
        if TerminalSize::new(cols, rows).is_ok() && resize.try_resize(cols, rows).is_ok() {
            applied = Some((cols, rows));
        }
        consumed += RECORD_LEN;
    }
    buf.drain(..consumed);
    applied
}

/// Send a batch of outgoing datagrams. We ignore individual send errors on
/// this server: a single lost datagram shouldn't tear down the whole loop.
async fn send_all(socket: &UdpSocket, dgrams: &[Datagram]) {
    for dg in dgrams {
        let _ = socket.send_to(&dg.bytes, dg.to).await;
    }
}

/// The blocking loop: reads available bytes from the PTY and sends them into
/// the channel. Runs inside `spawn_blocking` -- `Read` on the PTY master
/// side is synchronous. Exits on EOF (`Ok(0)`), a read error, or once the
/// channel's receiver has been dropped (the loop already wound down).
fn pty_to_channel(mut reader: Box<dyn Read + Send>, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if tx.blocking_send(buf[..n].to_vec()).is_err() {
            return;
        }
    }
}

/// The blocking loop: pulls chunks from the channel and writes them to the
/// PTY. Runs inside `spawn_blocking` -- `Write` on the PTY master side is
/// synchronous. The input channel is unbounded, so receiving uses
/// `blocking_recv` on `UnboundedReceiver`. Exits once the channel closes
/// (the loop dropped `pty_in_tx`) or a PTY write fails (e.g. the shell has
/// already exited).
fn channel_to_pty(mut rx: mpsc::UnboundedReceiver<Vec<u8>>, mut writer: Box<dyn Write + Send>) {
    while let Some(chunk) = rx.blocking_recv() {
        if writer.write_all(&chunk).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_events, apply_resize_records, ResizeHandle};
    use crate::conn::{AuthPolicy, Connection, ConnectionConfig, Event, LinkState, Role};
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    /// Real serve_shell with blocking I/O, but no child process. The writer
    /// echoes through the reader so output and ECHO_ACK exercise the full loop.
    struct ReplacementReader(std::sync::mpsc::Receiver<Vec<u8>>);

    impl std::io::Read for ReplacementReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.recv() {
                Ok(bytes) => {
                    assert!(bytes.len() <= buf.len());
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Err(_) => Ok(0),
            }
        }
    }

    struct ReplacementWriter(std::sync::mpsc::Sender<Vec<u8>>);

    impl std::io::Write for ReplacementWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .send(bytes.to_vec())
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct SharedResize(std::sync::Arc<RecordingResize>);
    impl ResizeHandle for SharedResize {
        fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String> {
            self.0.try_resize(cols, rows)
        }
    }

    struct ReplacementRig {
        server: tokio::task::JoinHandle<()>,
        addr: std::net::SocketAddr,
        server_pub: [u8; 32],
        socket: tokio::net::UdpSocket,
        conn: Connection,
        parser: crate::shell_frame::ShellDeframer,
        output: Vec<u8>,
        ack: u64,
        confirmed: bool,
        resize: std::sync::Arc<RecordingResize>,
    }

    impl Drop for ReplacementRig {
        fn drop(&mut self) {
            // Abort drops pty_in_tx, releasing the blocking writer; its echo
            // sender then drops and releases the reader. No blocked worker is
            // left behind even when a RED assertion or timeout unwinds.
            self.server.abort();
        }
    }

    fn replacement_client(server_pub: [u8; 32], private: [u8; 32]) -> Connection {
        Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: private,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        })
    }

    impl ReplacementRig {
        async fn new(keys: &[crate::handshake::Keypair]) -> Self {
            let server_key = crate::handshake::generate_keypair();
            let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = server_socket.local_addr().unwrap();
            let (echo_tx, echo_rx) = std::sync::mpsc::channel();
            let resize = std::sync::Arc::new(RecordingResize::new());
            let server = tokio::spawn(super::serve_shell(
                server_socket,
                ConnectionConfig {
                    required_features: crate::Features::NONE,
                    features: crate::Features::SUPPORTED,
                    role: Role::Server,
                    local_static_priv: server_key.private,
                    remote_static_pub: None,
                    auth: AuthPolicy::Allowlist(keys.iter().map(|k| k.public).collect()),
                },
                Box::new(ReplacementReader(echo_rx)),
                Box::new(ReplacementWriter(echo_tx)),
                Box::new(SharedResize(resize.clone())),
            ));
            Self {
                server,
                addr,
                server_pub: server_key.public,
                socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                conn: replacement_client(server_key.public, keys[0].private),
                parser: crate::shell_frame::ShellDeframer::new(),
                output: Vec::new(),
                ack: 0,
                confirmed: false,
                resize,
            }
        }

        async fn transmit(&self, out: Vec<crate::Datagram>) {
            for dg in out {
                self.socket.send_to(&dg.bytes, dg.to).await.unwrap();
            }
        }

        async fn until(&mut self, ready: impl Fn(&Self) -> bool) {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let mut buf = [0; 8192];
                while !ready(self) {
                    let deadline = self.conn.next_timeout().unwrap_or_else(|| {
                        std::time::Instant::now() + std::time::Duration::from_secs(2)
                    });
                    let out = tokio::select! {
                        received = self.socket.recv_from(&mut buf) => {
                            let (n, from) = received.unwrap();
                            if self.conn.peek_frames(&buf[..n]).is_some_and(|frames| frames.iter().any(|frame| matches!(frame, crate::reliability::StreamFrame::Pong { .. }))) {
                                self.confirmed = true;
                            }
                            self.conn.on_datagram(std::time::Instant::now(), from, &buf[..n])
                        }
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                            self.conn.on_timeout(std::time::Instant::now())
                        }
                    };
                    self.transmit(out).await;
                    for ev in self.conn.poll_events() {
                        if let Event::StreamData { stream_id: 0, data } = ev {
                            for record in self.parser.push(&data) {
                                match record {
                                    crate::shell_frame::ShellRecord::Data(bytes) => {
                                        self.output.extend(bytes)
                                    }
                                    crate::shell_frame::ShellRecord::EchoAck(offset) => {
                                        self.ack = offset
                                    }
                                    _ => panic!("legacy shell sent a channel record"),
                                }
                            }
                        }
                    }
                }
            })
            .await
            .expect("active shell did not preserve I/O and echo accounting");
        }

        async fn connect(&mut self) {
            let out = self.conn.start(std::time::Instant::now(), self.addr);
            self.transmit(out).await;
            self.until(|rig| rig.conn.state() == LinkState::Live).await;
            self.confirmed = false;
            self.conn.request_ping(std::time::Instant::now());
            let proof = self.conn.on_timeout(std::time::Instant::now());
            self.transmit(proof).await;
            self.until(|rig| rig.confirmed).await;
        }

        async fn send(&mut self, stream: u8, data: &[u8]) {
            let out = self.conn.send(std::time::Instant::now(), stream, data);
            self.transmit(out).await;
        }

        async fn attack(&self, kind: u8) {
            let stranger = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let packet = match kind {
                0 => crate::wire::encode_handshake(crate::wire::Kind::HandshakeInit, &[]),
                1 => crate::wire::encode_handshake(crate::wire::Kind::HandshakeInit, &[0; 40]),
                2 => {
                    let key = crate::handshake::generate_keypair();
                    replacement_client(self.server_pub, key.private)
                        .start(std::time::Instant::now(), self.addr)
                        .remove(0)
                        .bytes
                }
                _ => unreachable!(),
            };
            stranger.send_to(&packet, self.addr).await.unwrap();
        }
    }

    async fn rejected_replacement_case(kind: u8) {
        let key = crate::handshake::generate_keypair();
        let mut rig = ReplacementRig::new(&[key]).await;
        rig.connect().await;
        let id = rig.conn.session_id();
        let resize = record(123, 45);
        rig.send(1, &resize[..2]).await;
        rig.send(0, b"before").await;
        rig.until(|r| r.output == b"before" && r.ack == 6).await;
        assert!(rig.resize.taken().is_empty());
        rig.attack(kind).await;
        rig.send(1, &resize[2..]).await;
        rig.send(0, b"after").await;
        rig.until(|r| r.output == b"beforeafter" && r.ack == 11)
            .await;
        assert_eq!(rig.conn.session_id(), id);
        assert_eq!(
            rig.resize.taken(),
            vec![(123, 45)],
            "the partial control record must survive rejection"
        );
    }

    #[tokio::test]
    async fn shell_replacement_empty_msg1_preserves_active_state() {
        rejected_replacement_case(0).await;
    }
    #[tokio::test]
    async fn shell_replacement_truncated_noise_preserves_active_state() {
        rejected_replacement_case(1).await;
    }
    #[tokio::test]
    async fn shell_replacement_unlisted_key_preserves_active_state() {
        rejected_replacement_case(2).await;
    }

    #[tokio::test]
    async fn shell_replayed_allowlist_handshake_preserves_active_state() {
        let key = crate::handshake::generate_keypair();
        let mut rig = ReplacementRig::new(&[key]).await;
        let initial = rig.conn.start(std::time::Instant::now(), rig.addr);
        let captured = initial[0].bytes.clone();
        rig.transmit(initial).await;
        rig.until(|r| r.conn.state() == LinkState::Live).await;
        let resize = record(123, 45);
        rig.send(1, &resize[..2]).await;
        rig.send(0, b"before").await;
        rig.until(|r| r.output == b"before" && r.ack == 6).await;
        let replay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        replay.send_to(&captured, rig.addr).await.unwrap();
        let mut response = [0; 256];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            replay.recv(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        // A valid captured msg1 has obtained new msg2, but no peer has proved
        // possession of those fresh keys. The original shell still owns state.
        rig.send(1, &resize[2..]).await;
        rig.send(0, b"after").await;
        rig.until(|r| r.output == b"beforeafter" && r.ack == 11)
            .await;
        assert_eq!(rig.resize.taken(), vec![(123, 45)]);
    }

    #[tokio::test]
    async fn shell_replacement_allowed_key_resets_only_connection_state() {
        let keys = [
            crate::handshake::generate_keypair(),
            crate::handshake::generate_keypair(),
        ];
        let mut rig = ReplacementRig::new(&keys).await;
        // Invalid candidates before the first session must not prevent admission.
        for kind in 0..3 {
            rig.attack(kind).await;
        }
        rig.connect().await;
        let partial = record(444, 55);
        rig.send(1, &partial[..2]).await;
        rig.send(0, b"old").await;
        rig.until(|r| r.output == b"old" && r.ack == 3).await;
        let old_id = rig.conn.session_id();
        let mut old = std::mem::replace(
            &mut rig.conn,
            replacement_client(rig.server_pub, keys[1].private),
        );
        let old_socket = std::mem::replace(
            &mut rig.socket,
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        );
        rig.parser = crate::shell_frame::ShellDeframer::new();
        rig.output.clear();
        rig.ack = 0;
        rig.connect().await;
        assert_ne!(rig.conn.session_id(), old_id);
        // Old stream offsets/partial control must not leak into the new session.
        for dg in old.send(std::time::Instant::now(), 1, &partial[2..]) {
            old_socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        rig.send(1, &record(100, 40)).await;
        rig.send(0, b"new").await;
        rig.until(|r| r.output == b"new" && r.ack == 3).await;
        assert_eq!(rig.resize.taken(), vec![(100, 40)]);
    }

    /// A resize handle for unit tests: records the sizes received.
    struct RecordingResize {
        sizes: Mutex<Vec<(u16, u16)>>,
    }

    impl RecordingResize {
        fn new() -> Self {
            RecordingResize {
                sizes: Mutex::new(Vec::new()),
            }
        }

        fn taken(&self) -> Vec<(u16, u16)> {
            self.sizes.lock().unwrap().clone()
        }
    }

    impl ResizeHandle for RecordingResize {
        fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String> {
            self.sizes.lock().unwrap().push((cols, rows));
            Ok(())
        }
    }

    fn record(cols: u16, rows: u16) -> Vec<u8> {
        let mut v = vec![0x01u8];
        v.extend_from_slice(&cols.to_be_bytes());
        v.extend_from_slice(&rows.to_be_bytes());
        v
    }

    struct FailingResize;
    impl ResizeHandle for FailingResize {
        fn try_resize(&self, _cols: u16, _rows: u16) -> Result<(), String> {
            Err("ioctl failed".into())
        }
    }
    #[test]
    fn legacy_shell_cannot_advertise_channel_geometry() {
        let cfg = super::legacy_shell_config(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED | crate::Features::CHANNEL_GEOMETRY,
            role: Role::Server,
            local_static_priv: [7; 32],
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        assert!(!cfg.features.contains(crate::Features::CHANNEL_GEOMETRY));
        assert_eq!(
            cfg.features.bits(),
            crate::Features::SUPPORTED.bits() & !crate::Features::CHANNEL_GEOMETRY.bits()
        );
    }

    #[test]
    fn failed_legacy_ioctl_is_not_reported_as_applied() {
        let mut buf = record(2, 2);
        assert_eq!(apply_resize_records(&mut buf, &FailingResize), None);
        assert!(buf.is_empty());
    }

    #[test]
    fn invalid_resize_records_never_reach_the_pty() {
        let r = RecordingResize::new();
        for (cols, rows) in [(0, 1), (2, 0), (1, 1), (513, 1), (2, 257)] {
            let mut buf = record(cols, rows);
            assert_eq!(apply_resize_records(&mut buf, &r), None);
            assert!(buf.is_empty());
        }
        assert!(r.taken().is_empty());
    }

    #[test]
    fn parses_single_resize_record() {
        let r = RecordingResize::new();
        let mut buf = record(100, 40);
        assert_eq!(apply_resize_records(&mut buf, &r), Some((100, 40)));
        assert_eq!(r.taken(), vec![(100, 40)]);
        assert!(buf.is_empty(), "a complete record is read in full");
    }

    #[test]
    fn parses_two_coalesced_records() {
        let r = RecordingResize::new();
        let mut buf = record(80, 24);
        buf.extend(record(120, 50));
        // The batch is a drag in progress: only the LAST size stands.
        assert_eq!(apply_resize_records(&mut buf, &r), Some((120, 50)));
        assert_eq!(r.taken(), vec![(80, 24), (120, 50)]);
        assert!(buf.is_empty());
    }

    #[test]
    fn keeps_partial_record_until_completed() {
        let r = RecordingResize::new();
        let full = record(90, 30);
        // Only the first half of the record arrives -- resize isn't applied yet.
        let mut buf = full[..3].to_vec();
        assert_eq!(
            apply_resize_records(&mut buf, &r),
            None,
            "an incomplete record applies nothing"
        );
        assert!(r.taken().is_empty(), "an incomplete record is not applied");
        assert_eq!(
            buf.len(),
            3,
            "the incomplete tail is kept until the rest arrives"
        );
        // The rest arrives -- now the record is complete and gets applied.
        buf.extend_from_slice(&full[3..]);
        assert_eq!(apply_resize_records(&mut buf, &r), Some((90, 30)));
        assert_eq!(r.taken(), vec![(90, 30)]);
        assert!(buf.is_empty());
    }

    #[test]
    fn resyncs_past_unknown_type_byte() {
        let r = RecordingResize::new();
        // A garbage byte before a valid record: a desync, followed by a
        // valid resize -- shifting by one byte recovers parsing.
        let mut buf = vec![0xFFu8];
        buf.extend(record(70, 20));
        assert_eq!(apply_resize_records(&mut buf, &r), Some((70, 20)));
        assert_eq!(r.taken(), vec![(70, 20)]);
    }

    /// Resize has to reach both the PTY and the model, or the model renders
    /// the wrong geometry after the next resize.
    #[test]
    fn apply_resize_records_reports_the_size_it_applied() {
        let mut buf = record(100, 40);
        let resize = RecordingResize::new();
        assert_eq!(apply_resize_records(&mut buf, &resize), Some((100, 40)));
        assert_eq!(resize.taken(), vec![(100, 40)]);
        // Two coalesced records: the LAST one is the size that stands.
        let mut buf = record(90, 30);
        buf.extend_from_slice(&record(120, 50));
        let resize = RecordingResize::new();
        assert_eq!(apply_resize_records(&mut buf, &resize), Some((120, 50)));
        // A partial record applies nothing.
        let mut buf = vec![0x01, 0x00];
        let resize = RecordingResize::new();
        assert_eq!(apply_resize_records(&mut buf, &resize), None);
    }

    /// Spec §4.14: a stream out of offset space ends the session the way a
    /// death does -- the connection abandoned without a `Close`, the loop
    /// told to drop it -- rather than staying `Live` with an output stream
    /// that refuses every write.
    #[test]
    fn an_exhausted_stream_ends_the_session_without_a_close() {
        let kp = crate::handshake::generate_keypair();
        let mut c = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        c.push_test_event(Event::OffsetSpaceExhausted { stream_id: 0 });
        let (pty_in_tx, _pty_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut consumed = 0u64;
        let mut control_buf = Vec::new();
        let ended = apply_events(
            &mut c,
            &mut consumed,
            &pty_in_tx,
            &mut control_buf,
            &RecordingResize::new(),
        );
        assert!(ended, "the loop drops the connection");
        assert_eq!(c.state(), LinkState::Closed);
        assert!(!c.closed_gracefully());
    }
}
