//! Async driver on top of the sans-IO `Connection` core: a minimal tokio echo
//! server for A SINGLE client. This is enough to prove roaming with one
//! client; multiplexing many clients and abuse protection are
//! later work.
//!
//! The driver holds a single `Connection` for the whole `serve_echo` call and
//! ties it to a real UDP socket: it reads datagrams, feeds them to the core
//! (`on_datagram`/`on_timeout`), sends everything the core returns, and for
//! every delivered `StreamData` sends the same bytes back (echo).
//!
//! Time. The `Connection` core runs on `std::time::Instant`. So `now` is
//! taken from `std::time::Instant::now()`, and to sleep until the core's
//! nearest timer (`next_timeout`) we convert the deadline into a duration and
//! `tokio::time::sleep` for it.

use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::UdpSocket;

use crate::conn::{Connection, ConnectionConfig, Datagram, Event, LinkState};
use crate::wire::{parse, Frame, Kind};

/// Receive buffer size for a single UDP datagram.
const RECV_BUF_LEN: usize = 64 * 1024;

/// What woke up the loop: a packet arrived (or a receive error) or a core
/// timer fired.
enum Wakeup {
    Packet(std::io::Result<(usize, SocketAddr)>),
    Timeout,
}

/// Serve the echo server on socket `socket` with config `cfg` (role must be
/// server). The function never returns: it runs the receive/send loop until
/// the task is canceled externally.
///
/// Incoming routing (via `wire::parse`):
/// - `HandshakeInit` -- RECREATE the server `Connection` from `cfg.clone()`
///   and feed it the packet. This naturally recovers from a lost handshake
///   response (msg2): the client retransmits msg1, the server hands back a
///   fresh msg2.
/// - `Transport` -- feed the current `Connection` (if there is none yet,
///   ignore).
///
/// Scope limitation (planned debt, NOT fixed here): recreating on any
/// well-formed `HandshakeInit` means a stray msg1 could reset a live session
/// (a soft denial of service). Acceptable for this single-client echo
/// server; multiplexing and protection come later. Handshake retransmit ON
/// THE CLIENT SIDE is the client timer loop's job, not the server's.
pub async fn serve_echo(socket: UdpSocket, cfg: ConnectionConfig) {
    let mut buf = vec![0u8; RECV_BUF_LEN];
    // A single connection for the whole serve_echo call. `None` until the
    // first HandshakeInit and after the session closes (ready for a new
    // client).
    let mut conn: Option<Connection> = None;

    loop {
        // The nearest timer of the current connection (if any).
        let next = conn.as_ref().and_then(Connection::next_timeout);

        let wakeup = match next {
            Some(deadline) => {
                let dur = deadline.saturating_duration_since(Instant::now());
                tokio::select! {
                    r = socket.recv_from(&mut buf) => Wakeup::Packet(r),
                    _ = tokio::time::sleep(dur) => Wakeup::Timeout,
                }
            }
            // No timers (no session, or it's closed) -- wait only for a packet.
            None => Wakeup::Packet(socket.recv_from(&mut buf).await),
        };

        let now = Instant::now();
        let mut out: Vec<Datagram> = Vec::new();

        match wakeup {
            Wakeup::Packet(Ok((len, src))) => {
                match parse(&buf[..len]) {
                    Ok(Frame::Handshake {
                        kind: Kind::HandshakeInit,
                        ..
                    }) => {
                        // A fresh server Connection on every msg1.
                        let mut fresh = Connection::new(cfg.clone());
                        out.extend(fresh.on_datagram(now, src, &buf[..len]));
                        conn = Some(fresh);
                    }
                    Ok(_) => {
                        if let Some(c) = conn.as_mut() {
                            out.extend(c.on_datagram(now, src, &buf[..len]));
                        }
                    }
                    // Malformed input from the network is silently ignored.
                    Err(_) => {}
                }
            }
            // Receive error -- nothing to process, the socket is still alive.
            // No `continue`: the timers below run after this wake-up too.
            Wakeup::Packet(Err(_)) => {}
            // Nothing of its own: the timers run after every wake-up, below.
            Wakeup::Timeout => {}
        }
        // Timers after every wake-up (spec §4.1).
        if let Some(c) = conn.as_mut() {
            out.extend(c.on_timeout_if_due(now));
        }

        send_all(&socket, &out).await;

        // Core events: echo delivered bytes and reset the session on close.
        let mut reset = false;
        if let Some(c) = conn.as_mut() {
            let events = c.poll_events();
            let mut echo: Vec<Datagram> = Vec::new();
            for ev in events {
                match ev {
                    Event::StreamData { stream_id, data } => {
                        echo.extend(c.send(now, stream_id, &data));
                    }
                    Event::StateChanged(LinkState::Closed) => reset = true,
                    _ => {}
                }
            }
            send_all(&socket, &echo).await;
        }
        if reset {
            conn = None;
        }
    }
}

/// Send a batch of outgoing datagrams. We ignore individual send errors on
/// this diagnostic echo server: a single lost datagram shouldn't tear down
/// the whole loop.
async fn send_all(socket: &UdpSocket, dgrams: &[Datagram]) {
    for dg in dgrams {
        let _ = socket.send_to(&dg.bytes, dg.to).await;
    }
}
