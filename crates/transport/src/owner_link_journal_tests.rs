//! The owner's custody journal and the rebuild of a frontend's bridge from
//! it (#529 M1): a session owner on one side of the real link, on the other
//! a frontend whose bridge state is the real `ChannelBridge`, rebuilt by the
//! real `rebuild_from_owner` and drained into a real connection pair.

use super::*;
use crate::channel_timeline::{EntryClass, TimelineBudget, TimelinePermit, BRIDGE_LIFECYCLE_BYTES};
use crate::control_budget::{ControlLedger, Response};
use crate::send_gate::GateKind;
use crate::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};
use std::time::Duration;

const STREAM: u8 = 16;

fn instance(n: u64) -> ChannelInstance {
    ChannelInstance::new(n).unwrap()
}

/// An owner backend that hands its io to the test and returns.
struct Capture(Mutex<Option<oneshot::Sender<SessionIo>>>);
impl SessionBackend for Capture {
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let tx = self.0.lock().unwrap().take();
        Box::pin(async move {
            if let Some(tx) = tx {
                let _ = tx.send(io);
            }
        })
    }
}

/// One end of a link that the test can cut: the other end then reads end of
/// input and fails its writes, as when the process holding this end dies.
#[derive(Clone)]
struct Cut {
    inner: Arc<Mutex<Option<LinkEnd>>>,
    waker: Arc<Mutex<Option<std::task::Waker>>>,
}
impl Cut {
    fn new(end: LinkEnd) -> Cut {
        Cut {
            inner: Arc::new(Mutex::new(Some(end))),
            waker: Arc::new(Mutex::new(None)),
        }
    }
    fn cut(&self) {
        self.inner.lock().unwrap().take();
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}
impl AsyncRead for Cut {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        match inner.as_mut() {
            Some(end) => {
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                Pin::new(end).poll_read(cx, buf)
            }
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}
impl AsyncWrite for Cut {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.inner.lock().unwrap().as_mut() {
            Some(end) => Pin::new(end).poll_write(cx, buf),
            None => std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.inner.lock().unwrap().as_mut() {
            Some(end) => Pin::new(end).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.inner.lock().unwrap().as_mut() {
            Some(end) => Pin::new(end).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

/// Gives the owner a new loopback link, and remembers the frontend's end so
/// the test can cut it.
struct TestRelink {
    owner: OwnerRelink,
    ends: Mutex<Vec<Cut>>,
    /// While set, the owner's end of a new link is kept here instead of
    /// reaching the owner: an owner that does not take its links.
    withhold: std::sync::atomic::AtomicBool,
    withheld: Mutex<Vec<LinkEnd>>,
}
impl TestRelink {
    fn link(&self) -> Cut {
        let (front, owner) = loopback();
        if self.withhold.load(Ordering::SeqCst) {
            self.withheld.lock().unwrap().push(owner);
        } else {
            self.owner.relink(owner);
        }
        let cut = Cut::new(front);
        self.ends.lock().unwrap().push(cut.clone());
        cut
    }
    fn cut_current(&self) {
        if let Some(end) = self.ends.lock().unwrap().last() {
            end.cut();
        }
    }
}
impl FrontendRelink for TestRelink {
    fn exited(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(std::future::ready(false))
    }
    fn relink(&self) -> std::io::Result<Box<dyn LinkIo>> {
        Ok(Box::new(self.link()))
    }
}

/// The frontend's side of one session: what a bridge task holds.
struct Front {
    out: mpsc::UnboundedReceiver<SessionOutbound>,
    control: Arc<SessionControl>,
    mailbox: channel_bridge::SnapshotMailbox,
    inbound: Option<CreditSender>,
    lifecycle: Arc<Lifecycle>,
    bridge: channel_bridge::ChannelBridge,
    pending_control: VecDeque<PendingControl>,
    generation: u64,
    /// `Consumed` reports that reached this frontend.
    consumed: Vec<(u8, usize)>,
    lost: bool,
}

/// The client's side: a connection pair and what the client decoded.
struct Net {
    server: Connection,
    client: Connection,
    peer: SocketAddr,
    now: Instant,
    frames: ShellDeframer,
    records: Vec<ShellRecord>,
    control_frames: RecordDeframer,
    control_records: Vec<crate::channel::ServerRecord>,
    control_delivery: ControlLedger,
}
impl Net {
    fn new(generation: u64) -> Net {
        let peer: SocketAddr = "192.0.2.1:41000".parse().unwrap();
        let kp = crate::handshake::generate_keypair();
        let (mut client, server, out) = super::super::tests::accepted_connection_with(
            &kp,
            [1; 16],
            peer,
            crate::Features::SUPPORTED | crate::Features::CHANNEL_GEOMETRY,
        );
        for dg in out {
            client.on_datagram(Instant::now(), peer, &dg.bytes);
        }
        Net {
            server,
            client,
            peer,
            now: Instant::now(),
            frames: ShellDeframer::new(),
            records: Vec::new(),
            control_frames: RecordDeframer::for_control(),
            control_records: Vec::new(),
            control_delivery: ControlLedger::new(generation, 0),
        }
    }

    /// Carry `out` to the client and, unless `silent`, its acknowledgements
    /// back, until nothing moves.
    fn pump(&mut self, mut out: Vec<Datagram>, silent: bool) {
        for _ in 0..100 {
            for dg in std::mem::take(&mut out) {
                for ack in self.client.on_datagram(self.now, self.peer, &dg.bytes) {
                    if !silent {
                        out.extend(self.server.on_datagram(self.now, self.peer, &ack.bytes));
                    }
                }
            }
            for ev in self.client.poll_events() {
                if let Event::StreamData { stream_id, data } = ev {
                    if stream_id == STREAM {
                        self.records.extend(self.frames.push(&data));
                    } else if stream_id == crate::channel::CONTROL_STREAM {
                        self.control_records.extend(
                            self.control_frames
                                .push(&data)
                                .iter()
                                .filter_map(|raw| crate::channel::decode_server(raw).ok()),
                        );
                    }
                }
            }
            if silent {
                break;
            }
            self.now += Duration::from_millis(20);
            for ack in self.client.on_timeout(self.now) {
                out.extend(self.server.on_datagram(self.now, self.peer, &ack.bytes));
            }
            out.extend(self.server.on_timeout(self.now));
            if out.is_empty() && self.server.stream_progress(STREAM).unacked == 0 {
                break;
            }
        }
    }
}

struct Rig {
    /// The runner's io, in the owner.
    owner: SessionIo,
    relink: Arc<TestRelink>,
    front: Front,
    net: Net,
    gate: Arc<SendGate>,
    budget: TimelineBudget,
    /// Input the backend received ahead of a `ResumeReset`.
    input: Vec<u8>,
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(30)).await;
}

async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..2000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The backend's next inbound event, past the wakes the owner makes on its
/// own (`Writable`, `OutputReady`).
async fn next_in(owner: &mut SessionIo) -> SessionInbound {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(2), owner.recv())
            .await
            .expect("an owner inbound event")
            .expect("the owner's inbound queue is open");
        if !matches!(
            event,
            SessionInbound::Writable { .. } | SessionInbound::OutputReady { .. }
        ) {
            return event;
        }
    }
}

/// A frontend on `link`: its io, the link's reader task and the bridge's
/// sender. `replaces` as for `start_frontend`.
fn frontend(link: Cut, relink: &Arc<TestRelink>, replaces: bool) -> Front {
    let (io, _unused_queue, out) = SessionIo::test_pair();
    let lifecycle = io.lifecycle.clone();
    let control = io.control().clone();
    let mailbox = io.resume_snapshots.clone();
    let relink: Arc<dyn FrontendRelink> = relink.clone();
    lifecycle
        .clone()
        .spawn(start_frontend(io, Box::new(link), Some(relink), replaces));
    let inbound = control
        .remote
        .get()
        .and_then(|remote| remote.take_inbound())
        .expect("the link installs the bridge's sender");
    let mut bridge = channel_bridge::ChannelBridge::starting_at(0);
    bridge.snapshots = mailbox.clone();
    Front {
        out,
        control,
        mailbox,
        inbound: Some(inbound),
        lifecycle,
        bridge,
        pending_control: VecDeque::new(),
        generation: 0,
        consumed: Vec::new(),
        lost: false,
    }
}

impl Rig {
    async fn new() -> Rig {
        let lifecycle = Lifecycle::new(Shutdown::default());
        let (tx, rx) = oneshot::channel();
        let init = OwnerInit {
            principal: Principal {
                uid: 0,
                name: "test".to_string(),
                identity: "test".to_string(),
                incarnation: 0,
            },
            login: [0; 16],
            last_generation: 0,
            lifecycle: Some(lifecycle.clone()),
            relinks: OwnerRelink::default(),
        };
        let relink = Arc::new(TestRelink {
            owner: init.relinks(),
            ends: Mutex::new(Vec::new()),
            withhold: Default::default(),
            withheld: Mutex::new(Vec::new()),
        });
        let (front_end, owner_end) = loopback();
        let first = Cut::new(front_end);
        relink.ends.lock().unwrap().push(first.clone());
        let backend = Arc::new(Capture(Mutex::new(Some(tx))));
        lifecycle.spawn(async move {
            OwnerLink::run(owner_end, backend, init).await;
        });
        let front = frontend(first, &relink, false);
        let owner = rx.await.expect("owner io");
        let gate = owner.send_gate(STREAM, GateKind::Pipe);
        let net = Net::new(0);
        let mut rig = Rig {
            owner,
            relink,
            front,
            net,
            gate,
            budget: TimelineBudget::new(instance(1), 0, |_| {}),
            input: Vec::new(),
        };
        // The session's first attachment.
        let context = rig.context();
        assert!(
            rig.front
                .inbound
                .as_ref()
                .unwrap()
                .try_send(SessionInbound::Live(context))
                .is_ok(),
            "credit for Live"
        );
        match next_in(&mut rig.owner).await {
            SessionInbound::Live(seen) => assert_eq!(seen, context),
            _ => panic!("the owner's backend hears Live first"),
        }
        rig
    }

    fn context(&self) -> AttachmentContext {
        AttachmentContext::for_connection(&self.net.server, self.front.generation)
    }

    /// The origin the runner stamps its records with.
    fn origin(&self) -> AttachmentContext {
        self.owner.processed_attachment()
    }

    fn emit(&self, output: ChannelOutput, reserve: Option<TimelinePermit>) {
        self.owner.send_channel_output(
            STREAM,
            instance(1),
            self.origin(),
            self.gate.clone(),
            output,
            reserve,
        );
    }

    /// The instance's first record: its geometry, with the gap reserve.
    fn open(&self, cols: u16) {
        let reserve = self
            .budget
            .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES);
        let permit = self.budget.try_reserve(EntryClass::Ordinary, 27).unwrap();
        self.emit(
            ChannelOutput::Geometry(
                GeometryRecord {
                    instance: instance(1),
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols,
                    rows: 24,
                },
                permit,
            ),
            reserve,
        );
    }

    fn data(&self, bytes: &[u8]) {
        self.emit(ChannelOutput::Data(bytes.to_vec()), None);
    }

    /// Take what the owner sent so far into the bridge, as the bridge's
    /// loop does.
    async fn intake(&mut self) {
        settle().await;
        while let Ok(message) = self.front.out.try_recv() {
            match message {
                message @ (SessionOutbound::ChannelOutput { .. }
                | SessionOutbound::ChannelExit { .. }
                | SessionOutbound::ChannelClosed { .. }
                | SessionOutbound::ResumeSnapshotReady) => self.front.bridge.push(message),
                SessionOutbound::Resyncable {
                    stream_id,
                    resyncable,
                } => self.front.bridge.declare(stream_id, resyncable),
                SessionOutbound::ReservedSessionControl { bytes, delivery } => {
                    self.front.pending_control.push_back(PendingControl {
                        origin: None,
                        bytes,
                        delivery,
                        committed: None,
                    })
                }
                SessionOutbound::Consumed { stream_id, n } => {
                    self.front.consumed.push((stream_id, n))
                }
                SessionOutbound::Replay(step) => {
                    assert!(matches!(*step.0, Replay::Lost), "a step outside a rebuild");
                    self.front.lost = true;
                }
                _ => {}
            }
        }
    }

    /// One bridge turn: admit what fits, carry it to the client (whose
    /// acknowledgements come back unless `silent`), then the end-of-turn
    /// refresh and the bridge's notifications to the backend.
    fn turn(&mut self, silent: bool) {
        let mut out = Vec::new();
        self.front.bridge.drain(
            &mut self.net.server,
            self.net.now,
            false,
            &mut out,
            &mut self.net.control_delivery,
        );
        self.net.pump(out, silent);
        self.front.bridge.refresh(&self.net.server, false);
        for event in self.front.bridge.notifications() {
            let _ = self.front.inbound.as_ref().unwrap().try_send(event);
        }
    }

    async fn drain(&mut self) {
        self.intake().await;
        for _ in 0..4 {
            self.turn(false);
        }
        settle().await;
    }

    /// The new attachment after a rebuild: the ordinary `attach`, a new
    /// connection, and `ResumeReset`; the runner then publishes the
    /// attachment's snapshot, which releases the bridge's barrier.
    async fn attach(&mut self, rebuilt: Rebuilt) {
        self.front.generation = rebuilt.generation;
        self.front.bridge = rebuilt.channel_output;
        self.front.pending_control = rebuilt.pending_control;
        self.front
            .bridge
            .attach(&self.net.server, rebuilt.generation);
        self.net = Net::new(rebuilt.generation);
        let context = self.context();
        assert!(
            self.front
                .inbound
                .as_ref()
                .unwrap()
                .try_send(SessionInbound::ResumeReset(context))
                .is_ok(),
            "credit for ResumeReset"
        );
        loop {
            match next_in(&mut self.owner).await {
                SessionInbound::ResumeReset(seen) => break assert_eq!(seen, context),
                // Input the replaced connection delivered comes first.
                SessionInbound::Data(data) => self.input.extend(data.data),
                _ => panic!("the backend hears ResumeReset on the new attachment"),
            }
        }
        assert!(
            self.budget
                .reset_attachment(instance(1), context.generation),
            "the runner's timeline accepts generation {}",
            context.generation
        );
        assert!(self.owner.publish_resume_snapshot(context, || {
            crate::channel::ChannelSnapshot::new(Vec::new(), Vec::new())
        }));
    }

    /// A warm reattach in a frontend that lives on: the orderly handoff
    /// (or, after a lost link, the same without exact reports).
    async fn reattach(&mut self) {
        let remote = self.front.control.remote.get().unwrap();
        self.front.bridge.observe_discards(&mut self.net.server);
        if !remote.lost() {
            self.front.bridge.report_unconfirmed(&self.net.server);
        }
        let (sender, _lost) = remote.relink().expect("a new link");
        self.front.inbound = Some(sender);
        let rebuilt = tokio::time::timeout(
            Duration::from_secs(2),
            rebuild_from_owner(
                &mut self.front.out,
                self.front.mailbox.clone(),
                self.front.generation,
            ),
        )
        .await
        .expect("the owner's replay")
        .expect("a rebuilt bridge");
        self.attach(rebuilt).await;
    }

    /// The frontend process dies, and a new one takes the session over: a
    /// new link that replaces the dead one, and a bridge built from the
    /// owner's replay alone.
    async fn new_frontend(&mut self) {
        self.relink.cut_current();
        settle().await;
        let link = self.relink.link();
        let mut front = frontend(link, &self.relink, true);
        let rebuilt = tokio::time::timeout(
            Duration::from_secs(2),
            rebuild_from_owner(&mut front.out, front.mailbox.clone(), 0),
        )
        .await
        .expect("the owner's replay")
        .expect("a rebuilt bridge");
        self.front = front;
        self.attach(rebuilt).await;
    }

    fn data_records(&self) -> Vec<Vec<u8>> {
        self.net
            .records
            .iter()
            .filter_map(|record| match record {
                ShellRecord::Data(data) => Some(data.clone()),
                _ => None,
            })
            .collect()
    }

    fn gaps(&self) -> usize {
        self.net
            .records
            .iter()
            .filter(|record| matches!(record, ShellRecord::OutputGap { .. }))
            .count()
    }
}

/// [RF 1] A session recovered twice in a row by new frontends keeps its
/// attachment generations growing: each rebuild continues from the highest
/// generation the owner has seen, so the runner accepts every new
/// attachment, its origins stay current, and nothing of an earlier one
/// becomes current again.
#[tokio::test]
async fn recovered_twice_keeps_generations_monotonic() {
    let mut rig = Rig::new().await;
    rig.open(80);
    rig.data(b"before");
    rig.drain().await;
    assert_eq!(rig.data_records(), [b"before".to_vec()]);
    let mut seen = vec![rig.front.generation];
    for round in 1..=2u64 {
        rig.new_frontend().await;
        // `attach` checked that the runner's timeline took the generation.
        seen.push(rig.front.generation);
        assert_eq!(rig.front.generation, round, "one more per recovery");
        assert_eq!(rig.origin().generation, round, "the backend's origin");
        // Output of the new attachment is current for the rebuilt bridge.
        let line = format!("after {round}");
        rig.data(line.as_bytes());
        rig.drain().await;
        assert_eq!(
            rig.data_records().last().map(Vec::as_slice),
            Some(line.as_bytes()),
            "round {round}: {:?}",
            rig.net.records
        );
    }
    assert_eq!(seen, [0, 1, 2]);
    // An earlier generation cannot come back.
    assert!(!rig.budget.reset_attachment(instance(1), 1));
    // The same through the orderly handoff of a frontend that lives on.
    rig.reattach().await;
    assert_eq!(rig.front.generation, 3);
    rig.reattach().await;
    assert_eq!(rig.front.generation, 4);
}

/// Output the earlier bridge still held crosses again in its order, behind
/// the stream's bootstrap geometry and the gap warning for what the old
/// connection had sent without acknowledgement; what the old connection
/// carried is not sent twice.
#[tokio::test]
async fn replay_preserves_output_order_and_gap() {
    for lost in [false, true] {
        let mut rig = Rig::new().await;
        rig.open(80);
        rig.data(b"one");
        rig.drain().await;
        assert_eq!(rig.data_records(), [b"one".to_vec()]);
        // "two" goes out, and its acknowledgement never comes back.
        rig.data(b"two");
        rig.intake().await;
        rig.turn(true);
        settle().await;
        // "three" and "four" reach the bridge and wait there.
        rig.data(b"three");
        rig.data(b"four");
        rig.intake().await;
        let charged = rig.gate.pending_for_test();
        assert_eq!(charged, 10 + 9, "the owner still charges the two records");

        if lost {
            // The frontend's end dies; the bridge that lives on parks and
            // takes a new link at the client's return.
            rig.relink.cut_current();
            rig.intake().await;
            assert!(rig.front.lost, "the bridge hears the link was lost");
            // While nobody is linked the backend goes on.
            rig.data(b"five");
            settle().await;
        }
        rig.reattach().await;
        rig.drain().await;
        rig.drain().await;

        // After a lost link, output that had crossed it is not sent again
        // (its report may be what was lost): the gap stands for it.
        let expected: Vec<Vec<u8>> = if lost {
            vec![b"five".to_vec()]
        } else {
            vec![b"three".to_vec(), b"four".to_vec()]
        };
        assert!(
            matches!(&rig.net.records[0], ShellRecord::Geometry(g) if g.request_id == 0 && g.cols == 80),
            "lost={lost}: the frontier's geometry first: {:?}",
            rig.net.records
        );
        assert!(
            matches!(
                &rig.net.records[1],
                ShellRecord::OutputGap {
                    cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
                    ..
                }
            ),
            "lost={lost}: then the gap: {:?}",
            rig.net.records
        );
        assert_eq!(rig.gaps(), 1, "lost={lost}");
        assert_eq!(rig.data_records(), expected, "lost={lost}");
        eventually("every replayed charge to settle", || {
            rig.gate.pending_for_test() == 0
        })
        .await;
    }
}

/// Without unacknowledged output, an orderly handoff owes no gap: its
/// confirmation report is exact.
#[tokio::test]
async fn an_orderly_handoff_of_confirmed_output_reports_no_gap() {
    let mut rig = Rig::new().await;
    rig.open(80);
    rig.data(b"one");
    rig.drain().await;
    rig.data(b"two");
    rig.intake().await;
    rig.reattach().await;
    rig.drain().await;
    rig.drain().await;
    assert_eq!(rig.gaps(), 0, "{:?}", rig.net.records);
    assert_eq!(rig.data_records(), [b"two".to_vec()]);
    // And once more, with nothing queued at all: the stream's state alone.
    rig.reattach().await;
    rig.drain().await;
    rig.data(b"three");
    rig.drain().await;
    assert!(
        matches!(&rig.net.records[0], ShellRecord::Geometry(g) if g.cols == 80),
        "{:?}",
        rig.net.records
    );
    assert_eq!(rig.gaps(), 0);
    assert_eq!(rig.data_records(), [b"three".to_vec()]);
}

/// Bytes a replaced link handed the backend are the replaced connection's:
/// the backend's reports pay them first, and only what is left credits the
/// connection of the new link.
#[tokio::test]
async fn owed_consumption_is_paid_before_new_credit() {
    for lost in [false, true] {
        let mut rig = Rig::new().await;
        let old = SessionInbound::Data(StreamData {
            stream_id: STREAM,
            data: vec![1; 100],
        });
        assert!(
            rig.front.inbound.as_ref().unwrap().try_send(old).is_ok(),
            "credit"
        );
        assert!(matches!(
            next_in(&mut rig.owner).await,
            SessionInbound::Data(_)
        ));
        // 30 of them are reported, and credit the first connection.
        rig.owner.consumed(STREAM, 30);
        rig.intake().await;
        assert_eq!(rig.front.consumed, [(STREAM, 30)]);
        if lost {
            rig.new_frontend().await;
        } else {
            rig.reattach().await;
        }
        rig.front.consumed.clear();
        // The new connection delivers 40 bytes.
        let new = SessionInbound::Data(StreamData {
            stream_id: STREAM,
            data: vec![2; 40],
        });
        assert!(
            rig.front.inbound.as_ref().unwrap().try_send(new).is_ok(),
            "credit"
        );
        assert!(matches!(
            next_in(&mut rig.owner).await,
            SessionInbound::Data(_)
        ));
        // 70 old bytes are still owed: a report within them credits nobody.
        rig.owner.consumed(STREAM, 50);
        rig.intake().await;
        assert_eq!(rig.front.consumed, [], "lost={lost}: owed bytes paid");
        // The next report pays the last 20 owed, and 15 of the new 40.
        rig.owner.consumed(STREAM, 35);
        rig.intake().await;
        assert_eq!(rig.front.consumed, [(STREAM, 15)], "lost={lost}");
        rig.owner.consumed(STREAM, 25);
        rig.intake().await;
        assert_eq!(
            rig.front.consumed,
            [(STREAM, 15), (STREAM, 25)],
            "lost={lost}: nothing more is owed"
        );
    }
}

fn exit_part(owner: &SessionIo) -> crate::control_budget::ResponsePart {
    owner
        .control_budget()
        .reserve(Response::Ordinary(10))
        .unwrap()
        .into_owner()
        .take_record(10)
        .unwrap()
}

/// A channel whose final marker was delivered: a rebuilt bridge owes each
/// new attachment a fresh delivery proof from the same marker. When the
/// child then exits while no frontend is linked, the exit the owner kept
/// goes out after the channel's output on the next link -- once.
#[tokio::test]
async fn a_delivered_marker_and_a_later_exit_survive_a_lost_link() {
    let mut rig = Rig::new().await;
    rig.open(80);
    rig.data(b"last output");
    let marker = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
    rig.emit(
        ChannelOutput::DeliveryMarker(DeliveryMarker { token: 7 }, marker),
        None,
    );
    rig.drain().await;
    rig.drain().await;
    match next_in(&mut rig.owner).await {
        SessionInbound::Delivered {
            stream: STREAM,
            token: 7,
            generation: 0,
        } => {}
        _ => panic!("the marker's delivery proof"),
    }
    let held = rig.budget.usage(EntryClass::Lifecycle);

    // The frontend dies; the child still runs. The next frontend's bridge
    // holds the marker where the dead one did, and proves delivery anew.
    rig.new_frontend().await;
    assert_eq!(
        rig.budget.usage(EntryClass::Lifecycle),
        held,
        "the marker's permit stays with the owner"
    );
    rig.drain().await;
    rig.drain().await;
    match next_in(&mut rig.owner).await {
        SessionInbound::Delivered {
            stream: STREAM,
            token: 7,
            generation: 1,
        } => {}
        _ => panic!("a fresh delivery proof for the new attachment"),
    }
    assert!(
        matches!(&rig.net.records[0], ShellRecord::Geometry(g) if g.cols == 80),
        "{:?}",
        rig.net.records
    );
    assert!(rig.data_records().is_empty(), "no output is sent twice");

    // That frontend dies too, and now the child exits with nobody linked.
    rig.relink.cut_current();
    settle().await;
    let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap();
    rig.owner.send_channel_exit(
        crate::channel::DrainingChannel {
            stream: STREAM,
            instance: instance(1),
            open: OpenClassification {
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
            },
        },
        rig.origin(),
        Some(3),
        permit,
        exit_part(&rig.owner),
    );
    settle().await;
    rig.new_frontend().await;
    rig.drain().await;
    rig.drain().await;
    let exits = |rig: &Rig| {
        rig.net
            .control_records
            .iter()
            .filter(|record| {
                **record
                    == crate::channel::ServerRecord::Exit {
                        stream: STREAM,
                        code: 3,
                    }
            })
            .count()
    };
    assert_eq!(exits(&rig), 1, "{:?}", rig.net.control_records);
    // The bridge forgot the instance, and every reservation went back.
    eventually("the instance's reservations to return", || {
        rig.budget.usage(EntryClass::Lifecycle) == (0, 0)
    })
    .await;
    eventually("the instance's charges to return", || {
        rig.gate.pending_for_test() == 0
    })
    .await;

    // The next frontend finds nothing of the instance but its tombstone.
    rig.new_frontend().await;
    rig.drain().await;
    assert!(rig.net.records.is_empty(), "{:?}", rig.net.records);
    assert_eq!(exits(&rig), 0, "{:?}", rig.net.control_records);
}

/// A token of a retired link reports nothing: whatever its bridge drops
/// after the handoff, the owner's journal alone decides, and the record
/// crosses again exactly once.
#[tokio::test]
async fn tokens_of_a_retired_link_do_not_release_replayed_custody() {
    let mut rig = Rig::new().await;
    rig.open(80);
    rig.drain().await;
    rig.data(b"kept");
    settle().await;
    // The record waits in the bridge's queue, unread, across the handoff.
    let stale = rig.front.out.try_recv().expect("the record crossed");
    assert_eq!(rig.gate.pending_for_test(), 9);
    rig.reattach().await;
    // The old link's token goes now: the owner's charge must stay.
    drop(stale);
    settle().await;
    assert_eq!(rig.gate.pending_for_test(), 9, "still charged, once");
    rig.drain().await;
    rig.drain().await;
    assert_eq!(rig.data_records(), [b"kept".to_vec()]);
    eventually("the replayed charge to settle", || {
        rig.gate.pending_for_test() == 0
    })
    .await;
}

/// Reply custody across a replaced link: an outcome that was not bound to
/// an attachment and not yet enqueued crosses again; a reply the old
/// connection had enqueued, and an offer its attachment never accepted, go
/// with that connection.
#[tokio::test]
async fn reply_custody_follows_the_old_connection_or_the_journal() {
    let mut rig = Rig::new().await;
    let origin = rig.origin();
    let part = |owner: &SessionIo, response| {
        owner
            .control_budget()
            .reserve(response)
            .unwrap()
            .into_owner()
            .take_record(6)
            .unwrap()
    };
    let usage = |rig: &Rig| rig.owner.lifecycle.control_budget.retained_for_test();
    let before = usage(&rig);
    // An accepted operation's outcome, an attachment's reply, an offer.
    rig.owner
        .send_session_control(vec![9; 6], part(&rig.owner, Response::Ordinary(6)));
    rig.owner
        .send_reserved_control(origin, vec![8; 6], part(&rig.owner, Response::Ordinary(6)));
    let mut receipt = rig
        .owner
        .commit_update(origin, part(&rig.owner, Response::Update));
    rig.intake().await;
    assert_eq!(rig.front.pending_control.len(), 1);
    rig.new_frontend().await;
    // Only the outcome was replayed, with its bytes.
    assert_eq!(rig.front.pending_control.len(), 1);
    assert_eq!(rig.front.pending_control[0].bytes, vec![9; 6]);
    assert!(rig.front.pending_control[0].origin.is_none());
    assert!(
        matches!(
            receipt.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ),
        "the offer of the dead attachment is not accepted"
    );
    // The bridge enqueues the outcome: its custody goes on acknowledgement.
    // (The new attachment's snapshot holds reservations of its own.)
    rig.front.pending_control.clear();
    settle().await;
    drop(rig.front.mailbox.take(Some(rig.front.generation), true));
    eventually("every reply reservation to return", || {
        usage(&rig) == before
    })
    .await;
}

/// An orderly handoff while the session is busy both ways: output is
/// streaming (more than the link buffers), and input the old connection
/// delivered is on its way to the owner. The frontend closes the retired
/// link behind its `Retire`; the owner, whose own writes then fail, still
/// reads everything the frontend wrote. So no input is lost, no record the
/// old connection carried is sent again, each queued record crosses once in
/// order, and nobody is warned of a gap.
#[tokio::test]
async fn an_orderly_handoff_under_streaming_output_is_exact() {
    let mut rig = Rig::new().await;
    rig.open(80);
    rig.data(b"carried");
    rig.drain().await;
    assert_eq!(rig.data_records(), [b"carried".to_vec()]);
    // "reported" goes out and is acknowledged in a turn whose reports are
    // still in the frontend's queue when the handoff starts.
    rig.data(b"reported");
    rig.intake().await;
    rig.turn(false);
    assert_eq!(rig.data_records().last().unwrap(), b"reported");
    // Input on credit, and a burst of output the owner has yet to forward.
    let typed = SessionInbound::Data(StreamData {
        stream_id: STREAM,
        data: vec![7; 100],
    });
    assert!(rig.front.inbound.as_ref().unwrap().try_send(typed).is_ok());
    let burst: Vec<Vec<u8>> = (0..400u32)
        .map(|n| {
            let mut record = vec![b'a' + (n % 26) as u8; 1024];
            record[..4].copy_from_slice(&n.to_be_bytes());
            record
        })
        .collect();
    for record in &burst {
        rig.data(record);
    }
    rig.reattach().await;
    assert_eq!(
        rig.input,
        vec![7; 100],
        "the input sent on credit reaches the backend, ahead of ResumeReset"
    );
    for _ in 0..40 {
        rig.drain().await;
        if rig.data_records().len() >= burst.len() {
            break;
        }
    }
    assert_eq!(rig.gaps(), 0, "an orderly handoff owes no gap");
    assert_eq!(
        rig.data_records(),
        burst,
        "the queued records cross once, in order, and nothing sent before"
    );
    eventually("every charge to settle", || {
        rig.gate.pending_for_test() == 0
    })
    .await;
}

/// A link is lost between a record leaving for the client and the report
/// of it reaching the owner. The owner cannot tell: the record is given up
/// and the client warned of a gap, never sent the same bytes again. Output
/// that was produced with no link up never crossed, and follows.
#[tokio::test]
async fn a_lost_link_never_sends_pipe_output_twice() {
    for new_process in [false, true] {
        let mut rig = Rig::new().await;
        rig.open(80);
        rig.data(b"one");
        rig.drain().await;
        rig.data(b"two");
        rig.intake().await;
        // The link dies; then the bridge's turn sends "two" to the client.
        rig.relink.cut_current();
        settle().await;
        rig.turn(false);
        assert_eq!(rig.data_records(), [b"one".to_vec(), b"two".to_vec()]);
        rig.data(b"three");
        settle().await;
        if new_process {
            rig.new_frontend().await;
        } else {
            rig.intake().await;
            assert!(rig.front.lost);
            rig.reattach().await;
        }
        rig.drain().await;
        rig.drain().await;
        assert_eq!(
            rig.data_records(),
            [b"three".to_vec()],
            "new_process={new_process}: {:?}",
            rig.net.records
        );
        assert_eq!(rig.gaps(), 1, "the client is told output may be missing");
        eventually("the given-up record's charge to return", || {
            rig.gate.pending_for_test() == 0
        })
        .await;
    }
}

fn attach_of(conn: Connection) -> BridgeControl {
    let (tx, rx) = oneshot::channel();
    let _ = tx.send(CommittedAdmission(AuthAcceptance {
        session_id: conn.session_id(),
        disposition: SessionDisposition::Resumed,
    }));
    BridgeControl::Attach(Box::new(conn), Vec::new(), Vec::new(), rx)
}

/// What a bridge task holds besides its link, for `apply_control`.
#[derive(Default)]
struct Held {
    held_backend: Option<PendingBackend>,
    pending_control: VecDeque<PendingControl>,
    classes: BTreeMap<u8, StreamClass>,
    first_live_sent: bool,
}

async fn apply(rig: &mut Rig, link: &mut BackendLink, held: &mut Held) -> AttachResult {
    let new = Net::new(1);
    let mut state = BridgeState {
        control: &rig.front.control,
        lifecycle: &rig.front.lifecycle,
        backend_out_rx: &mut rig.front.out,
        held_backend: &mut held.held_backend,
        pending_control: &mut held.pending_control,
        classes: &mut held.classes,
        first_live_sent: &mut held.first_live_sent,
        backend_finished: false,
    };
    let (mut parked, mut out) = (false, Vec::new());
    apply_control(
        &mut rig.net.server,
        &mut parked,
        link,
        attach_of(new.server),
        &mut state,
        Instant::now(),
        &mut out,
    )
    .await
}

fn bridge_link(rig: &mut Rig) -> BackendLink {
    let sender = rig.front.inbound.take().expect("the bridge's sender");
    let mut link = BackendLink::starting_at(InboundTx::Remote(sender), Consumption::Explicit, 0);
    link.channel_output.snapshots = rig.front.mailbox.clone();
    link
}

/// The backend's inbound queue closes: the frontend ended the session.
async fn owner_hears_the_end(owner: &mut SessionIo) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), owner.recv()).await {
            Ok(None) => return,
            Ok(Some(_)) => {}
            Err(_) => panic!("the owner never heard the end of the session"),
        }
    }
}

/// An owner that never replays: the warm reattach gives the session up
/// after `REBUILD_TIMEOUT` instead of holding its bridge for good, and the
/// end of the session travels on the new link, where the owner finds it
/// whenever it takes the link.
#[tokio::test(start_paused = true)]
async fn a_reattach_whose_owner_never_replays_is_rejected_and_ends_the_session() {
    let mut rig = Rig::new().await;
    let mut link = bridge_link(&mut rig);
    rig.relink.withhold.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let result = apply(&mut rig, &mut link, &mut Held::default()).await;
    assert!(matches!(result, AttachResult::Rejected(_)));
    assert!(
        started.elapsed() >= REBUILD_TIMEOUT,
        "only after the bound: {:?}",
        started.elapsed()
    );
    // The bridge task ends: its link goes, and with it the inbound sender.
    drop(link);
    // The owner takes the link at last.
    let late = rig.relink.withheld.lock().unwrap().pop().expect("a link");
    rig.relink.owner.relink(late);
    owner_hears_the_end(&mut rig.owner).await;
}

/// A session torn down while its owner's link is lost: the bridge gives the
/// owner one more link to carry the end, so the owner does not keep the
/// session until the daemon stops.
#[tokio::test]
async fn a_lost_session_that_is_torn_down_still_ends_its_owner() {
    let mut rig = Rig::new().await;
    rig.relink.cut_current();
    rig.intake().await;
    assert!(rig.front.lost);
    let links = rig.relink.ends.lock().unwrap().len();
    end_lost_session(&rig.front.control);
    assert_eq!(rig.relink.ends.lock().unwrap().len(), links + 1);
    owner_hears_the_end(&mut rig.owner).await;
    // A session whose link is up needs no such thing.
    let rig = Rig::new().await;
    end_lost_session(&rig.front.control);
    assert_eq!(rig.relink.ends.lock().unwrap().len(), 1);
}

/// A reattach in the turn where the backend's end was read but not yet
/// served does not ask the owner for a replay that cannot come: the bridge
/// keeps its own state and finishes the session as a finished backend's.
#[tokio::test]
async fn a_reattach_behind_a_held_backend_end_does_not_relink() {
    let mut rig = Rig::new().await;
    let mut link = bridge_link(&mut rig);
    let mut held = Held {
        held_backend: Some(PendingBackend::Eof),
        ..Held::default()
    };
    let result = apply(&mut rig, &mut link, &mut held).await;
    assert!(matches!(result, AttachResult::Applied));
    assert_eq!(rig.relink.ends.lock().unwrap().len(), 1, "no new link");
    assert!(matches!(held.held_backend, Some(PendingBackend::Eof)));
    assert_eq!(link.ledger.generation(), 1, "the ordinary attach");
    // Without the held end the same reattach replaces the link.
    let mut rig = Rig::new().await;
    let mut link = bridge_link(&mut rig);
    let result = apply(&mut rig, &mut link, &mut Held::default()).await;
    assert!(matches!(result, AttachResult::Applied));
    assert_eq!(rig.relink.ends.lock().unwrap().len(), 2);
}

/// An owner's link end whose writes fail once the test says so, while what
/// the frontend wrote stays readable: the frontend closed its side.
struct BrokenWrites {
    inner: LinkEnd,
    broken: Arc<std::sync::atomic::AtomicBool>,
}
impl AsyncRead for BrokenWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for BrokenWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.broken.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn next_frame<R: AsyncRead + Unpin>(reader: &mut LinkReader<R>) -> ToFrontend {
    let frame = tokio::time::timeout(Duration::from_secs(2), reader.next())
        .await
        .expect("a frame from the owner")
        .expect("a readable link")
        .expect("the link is open");
    ToFrontend::decode(&frame).expect("a frontend frame")
}

/// The owner's own writes fail -- the frontend closed the retired link
/// behind its `Retire` -- before the owner has read what the frontend wrote
/// last. That is still an orderly end: the input sent on credit reaches the
/// backend, the `Retire` is read, and output that crossed the link is
/// replayed on the next one rather than given up as after a lost link.
#[tokio::test]
async fn an_owner_whose_writes_fail_still_reads_the_link_to_its_retire() {
    let lifecycle = Lifecycle::new(Shutdown::default());
    let (tx, rx) = oneshot::channel();
    let init = OwnerInit {
        principal: Principal {
            uid: 0,
            name: "test".to_string(),
            identity: "test".to_string(),
            incarnation: 0,
        },
        login: [0; 16],
        last_generation: 0,
        lifecycle: Some(lifecycle.clone()),
        relinks: OwnerRelink::default(),
    };
    let relinks = init.relinks();
    let (front_end, owner_end) = loopback();
    let broken = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let owner_end = BrokenWrites {
        inner: owner_end,
        broken: broken.clone(),
    };
    let backend = Arc::new(Capture(Mutex::new(Some(tx))));
    lifecycle.spawn(async move {
        OwnerLink::run(owner_end, backend, init).await;
    });
    let mut owner = rx.await.expect("owner io");
    let (read, mut write) = tokio::io::split(front_end);
    let mut reader = LinkReader::new(read);
    let mut credits = 0;
    while credits < 3 {
        if let ToFrontend::Grant { slots } = next_frame(&mut reader).await {
            credits += slots;
        }
    }

    // The owner's writes break; a record it forwards now finds that out.
    broken.store(true, Ordering::SeqCst);
    let gate = owner.send_gate(STREAM, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    let reserve = budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES);
    owner.send_channel_output(
        STREAM,
        instance(1),
        owner.processed_attachment(),
        gate.clone(),
        ChannelOutput::Data(b"crossed".to_vec()),
        reserve,
    );
    settle().await;

    // Only now does the owner get to read the frontend's last frames.
    let mut frames = Vec::new();
    for byte in [1u8, 2, 3] {
        encode(
            &ToOwner::Data {
                stream: STREAM,
                data: vec![byte; 10],
            },
            &mut frames,
        )
        .unwrap();
    }
    encode(&ToOwner::Retire, &mut frames).unwrap();
    write.write_all(&frames).await.unwrap();
    for byte in [1u8, 2, 3] {
        match next_in(&mut owner).await {
            SessionInbound::Data(data) => assert_eq!(data.data, vec![byte; 10]),
            _ => panic!("the input written before the end reaches the backend"),
        }
    }

    // The next link starts with a replay that still holds the record: the
    // old link ended in order.
    let (front_end, owner_end) = loopback();
    relinks.relink(owner_end);
    let (read, _write) = tokio::io::split(front_end);
    let mut reader = LinkReader::new(read);
    assert!(matches!(
        next_frame(&mut reader).await,
        ToFrontend::ReplayStart { .. }
    ));
    let mut replayed = Vec::new();
    loop {
        match next_frame(&mut reader).await {
            ToFrontend::ReplayItem(OutRecord::ChannelOutput {
                output: OutputBody::Data(data),
                ..
            }) => replayed.push(data),
            ToFrontend::ReplayUnconfirmed { .. } => panic!("an orderly end owes no gap"),
            ToFrontend::ReplayDone => break,
            _ => {}
        }
    }
    assert_eq!(replayed, [b"crossed".to_vec()]);
}
