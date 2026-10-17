//! Async interactive-shell server on top of the sans-IO `Connection` core: a
//! "blocking PTY <-> reliable transport" bridge for A SINGLE client.
//!
//! The shape of the server loop matches [`crate::driver_tokio::serve_echo`]
//! (select recv/timeout, recreating `Connection` on `HandshakeInit`, sending
//! outgoing datagrams, dispatching `poll_events`), but two more wakeup
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
//! (a different or restarted client) recreates the `Connection`, but does
//! NOT touch the shell or the PTY -- the new client reconnects to the same
//! live shell (a simple, safe choice: the transport can't spin up a PTY on
//! its own anyway). The unfinished control-stream buffer is reset in that
//! case.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::conn::{Connection, ConnectionConfig, Datagram, Event, LinkState};
use crate::shell_frame::{encode_record, REC_DATA, REC_ECHO_ACK};
use crate::wire::{parse, Frame, Kind};

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
    fn resize(&self, cols: u16, rows: u16);
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

    /// The terminal changed size. Called with the size just applied to the
    /// PTY, so the model and the PTY never disagree about geometry.
    fn resize(&mut self, cols: u16, rows: u16);

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
    fn resize(&mut self, _cols: u16, _rows: u16) {}
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
    // The PTY bridge: two blocking tasks + two channels. The PTY reader puts
    // chunks into `pty_out`, the PTY writer pulls chunks from `pty_in`.
    let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    // `pty_in` is UNbounded: a synchronous send from the loop never blocks
    // it, even if the PTY writer has stalled (see the module docs).
    let (pty_in_tx, pty_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let _reader_task = tokio::task::spawn_blocking(move || pty_to_channel(reader, pty_out_tx));
    let _writer_task = tokio::task::spawn_blocking(move || channel_to_pty(pty_in_rx, writer));

    let mut buf = vec![0u8; RECV_BUF_LEN];
    // A single connection. `None` until the first HandshakeInit and after
    // the session closes (ready for a new client).
    let mut conn: Option<Connection> = None;
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
        let next = conn.as_ref().and_then(Connection::next_timeout);

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

        match wakeup {
            Wakeup::Packet(Ok((len, src))) => match parse(&buf[..len]) {
                Ok(Frame::Handshake {
                    kind: Kind::HandshakeInit,
                    ..
                }) => {
                    // A fresh server Connection on every msg1. The shell and
                    // PTY are NOT touched -- a new client reconnects to the
                    // same live shell; only the previous session's
                    // unfinished control buffer is reset.
                    let mut fresh = Connection::new(cfg.clone());
                    out.extend(fresh.on_datagram(now, src, &buf[..len]));
                    conn = Some(fresh);
                    control_buf.clear();
                    input_consumed = 0;
                    last_acked = 0;
                }
                Ok(_) => {
                    if let Some(c) = conn.as_mut() {
                        out.extend(c.on_datagram(now, src, &buf[..len]));
                    }
                }
                // Malformed input from the network is silently ignored.
                Err(_) => {}
            },
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

        // Timers after every wake-up (spec §4.1).
        if let Some(c) = conn.as_mut() {
            out.extend(c.on_timeout_if_due(now));
        }
        send_all(&socket, &out).await;

        // Core events: bytes delivered on stream 0 are written to the PTY,
        // records on stream 1 are applied as resize, session close resets
        // conn.
        let reset = match conn.as_mut() {
            Some(c) => apply_events(
                c,
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
fn apply_events(
    c: &mut Connection,
    input_consumed: &mut u64,
    pty_in_tx: &mpsc::UnboundedSender<Vec<u8>>,
    control_buf: &mut Vec<u8>,
    resize: &dyn ResizeHandle,
) -> bool {
    let mut ended = false;
    for ev in c.poll_events() {
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
        resize.resize(cols, rows);
        applied = Some((cols, rows));
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
        fn resize(&self, cols: u16, rows: u16) {
            self.sizes.lock().unwrap().push((cols, rows));
        }
    }

    fn record(cols: u16, rows: u16) -> Vec<u8> {
        let mut v = vec![0x01u8];
        v.extend_from_slice(&cols.to_be_bytes());
        v.extend_from_slice(&rows.to_be_bytes());
        v
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
