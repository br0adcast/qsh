//! UDP recovery runs on its own thread, with an independent SSH worker.
//! Every connection's events reach the main loop through
//! a forwarder that stamps them with the connection's number: the main loop
//! drops anything from a connection it has let go, so an old link's late
//! bytes never land in the new one's channels.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;

use ::connect::reconnect::RoundEnd;
use ::connect::recovery_gate::{AddressId, RecoveryEpoch, SweepId};
use ::connect::Address;
use std::net::SocketAddr;

use crate::climb::{Climb, Climbed, Connected, Mode, Setup};
use crate::recovery::Recovery;
use crate::session::UiEvent;
use crate::ui_wait::UiSender;

/// How one background round ended.
// Handed over once per round and taken apart at once: the size of the large
// variant costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
pub enum Round {
    /// Back in the session: the login, and the channel its events arrive on.
    Connected {
        connected: Connected,
        events: Receiver<UiEvent>,
    },
    Failed {
        end: RoundEnd,
        line: Option<String>,
    },
}

/// The result and disconnection become authoritative before their wake.
struct Completion<T> {
    sender: Option<Sender<T>>,
    wake: Option<crate::input_wake::WakeSender>,
}
impl<T> Completion<T> {
    fn send(&self, value: T) -> Result<(), std::sync::mpsc::SendError<T>> {
        self.sender.as_ref().unwrap().send(value)?;
        if let Some(wake) = &self.wake {
            let _ = wake.notify();
        }
        Ok(())
    }
}
impl<T> Drop for Completion<T> {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(wake) = &self.wake {
            let _ = wake.notify();
        }
    }
}

/// Dropping an unfinished recovery cancels both workers. If a success was
/// already queued, detach it as well: nobody will drain its terminal bytes.
pub struct RoundTask {
    done: Receiver<(u64, Round)>,
    recovery: Arc<Recovery>,
}

impl RoundTask {
    pub fn try_recv(&self) -> Result<Round, std::sync::mpsc::TryRecvError> {
        let (revision, round) = self.done.try_recv()?;
        if self.recovery.interrupted(revision) {
            if let Round::Connected { connected, .. } = round {
                connected.attempt.detach();
            }
            return Err(std::sync::mpsc::TryRecvError::Disconnected);
        }
        Ok(round)
    }

    /// Read only after consuming a generation-validated authenticated result.
    pub fn endpoint(&self, address: usize) -> Option<SocketAddr> {
        self.recovery.endpoint(address)
    }

    pub fn update_endpoints(&self, epoch: RecoveryEpoch, endpoints: Vec<(AddressId, SocketAddr)>) {
        self.recovery.update_endpoints(epoch, endpoints);
    }

    pub fn take_warning(&self) -> Option<String> {
        self.recovery.take_warning()
    }

    pub fn activity(&self) -> crate::recovery::Activity {
        self.recovery.activity()
    }

    pub fn retry_now(&self) {
        self.recovery.retry_now();
    }
}

impl Drop for RoundTask {
    fn drop(&mut self) {
        self.recovery.stop();
        if let Ok((_, Round::Connected { connected, .. })) = self.done.try_recv() {
            connected.attempt.detach();
        }
    }
}

struct CancelOnDrop {
    recovery: Arc<Recovery>,
    armed: bool,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.recovery.stop();
        }
    }
}

/// Runs recovery number `round` on its own thread; the answer arrives on the
/// returned task. Progress goes to `progress` as `UiEvent::Reconnecting`, stamped
/// with `round`: it travels apart from the answer, so the main loop needs the number
/// to drop a message that arrives after its round is over.
///
/// Dropping the task cancels its workers without blocking the terminal thread.
pub fn spawn_round(
    setup: Arc<Setup>,
    addresses: Vec<Address>,
    first: usize,
    (cols, rows): (u16, u16),
    round: u64,
    progress: impl Into<UiSender>,
) -> RoundTask {
    let progress = progress.into();
    let epoch = RecoveryEpoch {
        connection: round,
        network: 0,
    };
    let recovery = Arc::new(Recovery::new(epoch, addresses.len()));
    launch(
        setup,
        addresses,
        first,
        (cols, rows),
        round,
        progress,
        epoch,
        recovery,
        false,
    )
}

/// Production recovery consumes the main loop's retained bounded DNS catalog.
#[allow(clippy::too_many_arguments)]
pub fn spawn_catalog_round(
    setup: Arc<Setup>,
    addresses: Vec<Address>,
    first: usize,
    size: (u16, u16),
    round: u64,
    progress: impl Into<UiSender>,
    epoch: RecoveryEpoch,
    membership: Vec<AddressId>,
    endpoints: Vec<(AddressId, SocketAddr)>,
    fresh_session: bool,
) -> RoundTask {
    let progress = progress.into();
    let recovery = Arc::new(Recovery::with_catalog(epoch, membership, endpoints));
    launch(
        setup,
        addresses,
        first,
        size,
        round,
        progress,
        epoch,
        recovery,
        fresh_session,
    )
}

#[allow(clippy::too_many_arguments)]
fn launch(
    setup: Arc<Setup>,
    addresses: Vec<Address>,
    first: usize,
    (cols, rows): (u16, u16),
    round: u64,
    progress: UiSender,
    epoch: RecoveryEpoch,
    recovery: Arc<Recovery>,
    fresh_session: bool,
) -> RoundTask {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    if let Some(wake) = progress.notifier() {
        recovery.set_notification(wake);
    }
    let done_tx = Completion {
        sender: Some(done_tx),
        wake: progress.notifier(),
    };
    let worker = recovery.clone();
    std::thread::Builder::new()
        .name("qsh-reconnect".into())
        .spawn(move || {
            let mut cancel = CancelOnDrop {
                recovery: worker.clone(),
                armed: true,
            };
            worker.spawn_ssh(setup.clone(), addresses.clone(), first);
            let mut udp_round = 0u64;
            loop {
                if worker.cancel.is_cancelled() {
                    return;
                }
                let started = Instant::now();
                let revision = worker.revision();
                udp_round += 1;
                let sweep = SweepId(udp_round);
                worker.begin_sweep(sweep);
                crate::log::log(&format!("recovery: UDP round {udp_round}"));
                let (tx, rx) = std::sync::mpsc::channel();
                let mut climb = Climb::new(
                    &setup,
                    addresses.clone(),
                    first,
                    Mode::Background {
                        progress: progress.clone(),
                        round,
                    },
                    cols,
                    rows,
                    tx,
                    &rx,
                )
                .recovering(&worker, epoch, sweep)
                .allow_new_session(fresh_session);
                let climbed = climb.run();
                if matches!(
                    climbed,
                    Climbed::Failed {
                        end: RoundEnd::AllFailed,
                        ..
                    }
                ) {
                    if !worker.wait_udp(started, revision) {
                        return;
                    }
                    continue;
                }
                let round = match climbed {
                    Climbed::Connected(connected) => Round::Connected {
                        connected,
                        events: rx,
                    },
                    Climbed::Failed { end, line } => Round::Failed { end, line },
                    Climbed::Exit(code) => {
                        unreachable!("a background round has no exit code ({code})")
                    }
                };
                // finish(Recovered) has already revoked SSH. Keep this task's
                // stamp active until the owner consumes or drops the result.
                if worker.interrupted(revision) {
                    if let Round::Connected { connected, .. } = round {
                        connected.attempt.detach();
                    }
                    if !worker.wait_udp(started, revision) {
                        return;
                    }
                    continue;
                }
                cancel.armed = false;
                if let Err(std::sync::mpsc::SendError((_, Round::Connected { connected, .. }))) =
                    done_tx.send((revision, round))
                {
                    connected.attempt.detach();
                    worker.stop();
                }
                return;
            }
        })
        .expect("start a reconnect round");
    RoundTask {
        done: done_rx,
        recovery,
    }
}

/// Moves every event of connection number `link` into the main loop's channel, wrapped
/// in `UiEvent::FromLink`, until the connection's senders are gone.
pub fn forward(link: u64, events: Receiver<UiEvent>, to: impl Into<UiSender>) {
    let to = to.into();
    std::thread::Builder::new()
        .name(format!("qsh-link-{link}"))
        .spawn(move || {
            for event in events {
                if to
                    .send(UiEvent::FromLink {
                        link,
                        event: Box::new(event),
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .expect("start the link forwarder");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn a_connection_s_events_arrive_stamped_with_its_number_and_in_order() {
        let (link_tx, link_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        forward(7, link_rx, tx);
        link_tx.send(UiEvent::Tick).unwrap();
        link_tx.send(UiEvent::Resumed).unwrap();
        drop(link_tx);
        let got: Vec<UiEvent> = (0..2)
            .map(|_| rx.recv_timeout(Duration::from_secs(5)).expect("forwarded"))
            .collect();
        assert_eq!(
            got,
            vec![
                UiEvent::FromLink {
                    link: 7,
                    event: Box::new(UiEvent::Tick)
                },
                UiEvent::FromLink {
                    link: 7,
                    event: Box::new(UiEvent::Resumed)
                },
            ]
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Disconnected),
            "the forwarder ends with the connection's senders"
        );
    }
    #[test]
    fn ui_wait_round_completion_and_panic_drop_wake_after_publication() {
        use std::os::fd::AsRawFd;
        for publish in [false, true] {
            let (mut reader, sender) = crate::input_wake::pair().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let completion = Completion {
                sender: Some(tx),
                wake: Some(sender),
            };
            let worker = std::thread::spawn(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    // Exercise the actual completion owner during worker unwind.
                    // resume_unwind avoids running the process-global panic hook.
                    let completion = completion;
                    if publish {
                        completion.send(7).unwrap();
                    } else {
                        std::panic::resume_unwind(Box::new(()));
                    }
                }))
                .is_err()
            });
            assert_eq!(worker.join().unwrap(), !publish);
            assert_eq!(
                rx.try_recv(),
                if publish {
                    Ok(7)
                } else {
                    Err(std::sync::mpsc::TryRecvError::Disconnected)
                }
            );
            let mut p = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut p, 1, 0) }, 1);
            reader.drain().unwrap();
        }
    }
}
