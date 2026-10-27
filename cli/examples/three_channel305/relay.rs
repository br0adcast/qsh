//! Opaque, bounded fixture-only UDP fault injection. Never a production route.
use serde::Serialize;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const MAX_DATAGRAM: usize = 65_536;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    NoLoss,
    LossReorder,
}
impl Case {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "no-loss" => Ok(Self::NoLoss),
            "loss-reorder" => Ok(Self::LossReorder),
            _ => Err("unknown functional case"),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Forward,
    Drop,
    Hold,
    Swap,
}
struct Schedule {
    case: Case,
    armed: bool,
    ordinal: u64,
}
impl Schedule {
    fn new(case: Case) -> Self {
        Self {
            case,
            armed: false,
            ordinal: 0,
        }
    }
    fn arm(&mut self) -> Result<(), &'static str> {
        if self.armed {
            return Err("relay already armed");
        }
        self.armed = true;
        Ok(())
    }
    fn server_packet(&mut self) -> Result<Decision, &'static str> {
        if self.armed {
            self.ordinal = self
                .ordinal
                .checked_add(1)
                .ok_or("relay ordinal overflow")?;
        }
        Ok(if self.case == Case::LossReorder && self.armed {
            match self.ordinal {
                3 => Decision::Drop,
                7 => Decision::Hold,
                8 => Decision::Swap,
                _ => Decision::Forward,
            }
        } else {
            Decision::Forward
        })
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Receipt {
    pub armed: bool,
    pub server_after_arm: u64,
    pub dropped: u64,
    pub held: u64,
    pub reordered: u64,
    pub held_high_water: usize,
    pub held_bytes: usize,
    pub canceled_held: u64,
}
#[derive(Debug, Serialize)]
pub struct Outcome {
    pub receipt: Receipt,
    pub error: Option<String>,
}
impl Outcome {
    pub fn qualified(&self, case: Case) -> bool {
        let r = &self.receipt;
        if self.error.is_some()
            || !r.armed
            || r.server_after_arm == 0
            || r.held_bytes != 0
            || r.canceled_held != 0
        {
            return false;
        }
        match case {
            Case::NoLoss => {
                r.dropped == 0 && r.held == 0 && r.reordered == 0 && r.held_high_water == 0
            }
            Case::LossReorder => {
                r.server_after_arm >= 8
                    && r.dropped == 1
                    && r.held == 1
                    && r.reordered == 1
                    && r.held_high_water > 0
                    && r.held_high_water <= MAX_DATAGRAM
            }
        }
    }
}

enum Command {
    Arm(oneshot::Sender<Result<(), &'static str>>),
    #[cfg(test)]
    Inspect(oneshot::Sender<Receipt>),
}
#[derive(Clone)]
pub struct Arm {
    control: mpsc::Sender<Command>,
}
impl Arm {
    pub async fn arm(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.control
            .send(Command::Arm(tx))
            .await
            .map_err(|_| "relay stopped before arm")?;
        rx.await
            .map_err(|_| "relay arm owner stopped")?
            .map_err(str::to_owned)
    }
}
pub struct Relay {
    pub address: SocketAddr,
    control: mpsc::Sender<Command>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Outcome>,
}
impl Relay {
    pub async fn start(server: SocketAddr, case: Case) -> io::Result<Self> {
        let front = UdpSocket::bind("127.0.0.1:0").await?;
        let address = front.local_addr()?;
        let back = UdpSocket::bind("127.0.0.1:0").await?;
        back.connect(server).await?;
        let (control, requests) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(run(front, back, case, requests, stopped));
        Ok(Self {
            address,
            control,
            stop: Some(stop),
            task,
        })
    }
    pub fn arm_handle(&self) -> Arm {
        Arm {
            control: self.control.clone(),
        }
    }
    #[cfg(test)]
    pub async fn arm(&self) -> Result<(), String> {
        self.arm_handle().arm().await
    }
    #[cfg(test)]
    async fn snapshot(&self) -> Result<Receipt, String> {
        let (tx, rx) = oneshot::channel();
        self.control
            .send(Command::Inspect(tx))
            .await
            .map_err(|_| "relay stopped")?;
        rx.await.map_err(|_| "relay stopped".to_owned())
    }
    pub async fn finish(mut self) -> Result<Outcome, String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.await.map_err(|_| "relay task failed".to_owned())
    }
}

fn store_held(held: &mut Option<Vec<u8>>, packet: &[u8]) -> Result<(), String> {
    if held.is_some() || packet.len() > MAX_DATAGRAM {
        return Err("relay held capacity exceeded".into());
    }
    *held = Some(packet.to_vec());
    Ok(())
}

async fn run(
    front: UdpSocket,
    back: UdpSocket,
    case: Case,
    mut control: mpsc::Receiver<Command>,
    mut stop: oneshot::Receiver<()>,
) -> Outcome {
    let mut schedule = Schedule::new(case);
    let mut receipt = Receipt::default();
    let mut held: Option<Vec<u8>> = None;
    let mut client = None;
    let mut front_buffer = vec![0; MAX_DATAGRAM];
    let mut back_buffer = vec![0; MAX_DATAGRAM];
    let result:Result<(),String>=async {
        loop {
            tokio::select! {
                biased;
                _=&mut stop=>return Ok(()),
                command=control.recv()=>match command {
                    Some(Command::Arm(reply))=>{let result=schedule.arm();receipt.armed=schedule.armed;let _=reply.send(result);}
                    #[cfg(test)]
                    Some(Command::Inspect(reply))=>{let _=reply.send(receipt);}
                    None=>return Ok(()),
                },
                packet=front.recv_from(&mut front_buffer)=>{
                    let (n,source)=packet.map_err(|_|"relay client receive failed")?;
                    if client.is_some_and(|known|known!=source) {return Err("relay received unrelated client".into());}
                    client=Some(source);
                    back.send(&front_buffer[..n]).await.map_err(|_|"relay client forwarding failed")?;
                },
                packet=back.recv(&mut back_buffer)=>{
                    let n=packet.map_err(|_|"relay server receive failed")?;
                    let target=client.ok_or("relay reply without client mapping")?;
                    let decision=schedule.server_packet().map_err(str::to_owned)?;
                    receipt.server_after_arm=schedule.ordinal;
                    match decision {
                        Decision::Forward=>{front.send_to(&back_buffer[..n],target).await.map_err(|_|"relay server forwarding failed")?;}
                        Decision::Drop=>{receipt.dropped+=1;}
                        Decision::Hold=>{
                            store_held(&mut held,&back_buffer[..n])?;
                            receipt.held+=1;receipt.held_bytes=n;receipt.held_high_water=receipt.held_high_water.max(n);
                        }
                        Decision::Swap=>{
                            let earlier=held.take().ok_or("relay missing held packet")?;
                            // Receipt commits only after both actual sends complete.
                            front.send_to(&back_buffer[..n],target).await.map_err(|_|"relay overtaking send failed")?;
                            front.send_to(&earlier,target).await.map_err(|_|"relay held send failed")?;
                            receipt.held_bytes=0;receipt.reordered+=1;
                        }
                    }
                },
            }
        }
    }.await;
    if held.take().is_some() {
        receipt.canceled_held += 1;
    }
    receipt.held_bytes = 0;
    Outcome {
        receipt,
        error: result.err(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn qualification305_relay_schedule_is_armed_directional_and_exact() {
        let mut schedule = Schedule::new(Case::LossReorder);
        for _ in 0..12 {
            assert_eq!(schedule.server_packet().unwrap(), Decision::Forward);
        }
        assert_eq!(schedule.ordinal, 0);
        schedule.arm().unwrap();
        assert!(schedule.arm().is_err());
        let decisions: Vec<_> = (0..10).map(|_| schedule.server_packet().unwrap()).collect();
        assert_eq!(
            decisions,
            vec![
                Decision::Forward,
                Decision::Forward,
                Decision::Drop,
                Decision::Forward,
                Decision::Forward,
                Decision::Forward,
                Decision::Hold,
                Decision::Swap,
                Decision::Forward,
                Decision::Forward
            ]
        );
    }
    #[test]
    fn qualification305_relay_no_loss_cannot_fabricate_faults() {
        let mut schedule = Schedule::new(Case::NoLoss);
        schedule.arm().unwrap();
        for _ in 0..20 {
            assert_eq!(schedule.server_packet().unwrap(), Decision::Forward);
        }
    }
    #[test]
    fn qualification305_relay_single_held_capacity_is_enforced_without_replacing_owner() {
        let mut held = None;
        store_held(&mut held, &[7]).unwrap();
        assert_eq!(held.as_deref(), Some([7].as_slice()));
        let pointer = held.as_ref().unwrap().as_ptr();
        assert!(store_held(&mut held, &[8]).is_err());
        assert_eq!(held.as_ref().unwrap().as_ptr(), pointer);
        held.take();
        assert!(store_held(&mut held, &vec![0; MAX_DATAGRAM + 1]).is_err());
        assert!(held.is_none());
    }
    async fn exercise(case: Case, count: u8) -> (Vec<u8>, Outcome) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = Relay::start(server.local_addr().unwrap(), case)
            .await
            .unwrap();
        let exercise = tokio::time::timeout(Duration::from_secs(2), async {
            client
                .send_to(&[99], relay.address)
                .await
                .map_err(|e| e.to_string())?;
            let mut buf = [0; MAX_DATAGRAM];
            let (n, back) = server
                .recv_from(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
            if &buf[..n] != [99] {
                return Err("client payload changed".to_owned());
            }
            // More than eight pre-arm replies must remain untouched and cannot
            // spend the later fixed schedule. Receipt arrives before arm ack.
            for _ in 0..9 {
                server
                    .send_to(&[42], back)
                    .await
                    .map_err(|e| e.to_string())?;
                let n = client.recv(&mut buf).await.map_err(|e| e.to_string())?;
                if &buf[..n] != [42] {
                    return Err("pre-arm reply changed".to_owned());
                }
            }
            relay.arm().await?;
            if !relay.snapshot().await?.armed {
                return Err("arm ack preceded processing".to_owned());
            }
            for ordinal in 1..=count {
                server
                    .send_to(&[ordinal], back)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let expected = if case == Case::LossReorder {
                usize::from(count) - usize::from(count >= 3) - usize::from(count == 7)
            } else {
                usize::from(count)
            };
            let mut received = Vec::new();
            for _ in 0..expected {
                let n = client.recv(&mut buf).await.map_err(|e| e.to_string())?;
                if n != 1 {
                    return Err("server payload changed".to_owned());
                }
                received.push(buf[0]);
            }
            if count == 7 {
                while relay.snapshot().await?.held_bytes == 0 {
                    tokio::task::yield_now().await;
                }
            }
            Ok::<_, String>(received)
        })
        .await;
        // Even failed/watchdog controls stop and join the owned relay before asserting.
        let outcome = relay.finish().await.unwrap();
        (
            exercise
                .expect("owned UDP watchdog")
                .expect("owned UDP exercise"),
            outcome,
        )
    }
    #[tokio::test]
    async fn qualification305_relay_owned_udp_really_drops_and_overtakes() {
        let (received, outcome) = exercise(Case::LossReorder, 8).await;
        assert_eq!(received, vec![1, 2, 4, 5, 6, 8, 7]);
        assert!(outcome.error.is_none());
        assert!(outcome.receipt.armed);
        assert_eq!(
            (
                outcome.receipt.dropped,
                outcome.receipt.held,
                outcome.receipt.reordered
            ),
            (1, 1, 1)
        );
        assert_eq!(outcome.receipt.held_high_water, 1);
        assert_eq!(outcome.receipt.held_bytes, 0);
        assert!(outcome.qualified(Case::LossReorder));
        assert!(!outcome.qualified(Case::NoLoss));
    }
    #[tokio::test]
    async fn qualification305_relay_owned_no_loss_preserves_order() {
        let (received, outcome) = exercise(Case::NoLoss, 8).await;
        assert_eq!(received, (1..=8).collect::<Vec<_>>());
        assert!(outcome.error.is_none());
        assert_eq!(
            (
                outcome.receipt.dropped,
                outcome.receipt.held,
                outcome.receipt.reordered
            ),
            (0, 0, 0)
        );
        assert!(outcome.qualified(Case::NoLoss));
        assert!(!outcome.qualified(Case::LossReorder));
    }
    #[tokio::test]
    async fn qualification305_relay_stop_discards_one_held_owner_and_joins() {
        let (received, outcome) = exercise(Case::LossReorder, 7).await;
        assert_eq!(received, vec![1, 2, 4, 5, 6]);
        assert_eq!(outcome.receipt.held_bytes, 0);
        assert_eq!(outcome.receipt.canceled_held, 1);
        assert_eq!(outcome.receipt.reordered, 0);
        assert!(!outcome.qualified(Case::LossReorder));
    }
}
