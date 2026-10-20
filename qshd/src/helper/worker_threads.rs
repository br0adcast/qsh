//! Fixed custody of the worker's four auxiliary threads.
//!
//! Thread joins are not a manager-drain or whole-service completion receipt.

use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    NoncePool = 0,
    ChannelReader = 1,
    AuthReader = 2,
    TellReleaser = 3,
}

fn discard_panic(payload: Box<dyn std::any::Any + Send>) {
    // Match retains a secondary payload until abort; do not let its destructor
    // unwind before abort and abandon another owned thread's join.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload))) {
        Ok(()) => {}
        Err(_secondary) => std::process::abort(),
    }
}

struct Thread {
    join: JoinHandle<io::Result<()>>,
    stop: Box<dyn FnOnce() -> io::Result<()> + Send>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct JoinedThreads {
    pub started: u8,
    pub joined: u8,
    pub panicked: u8,
    pub failed: u8,
}

#[derive(Default)]
#[must_use = "retain every auxiliary thread through its actual join"]
pub(crate) struct WorkerThreads {
    threads: [Option<Thread>; 4],
    result: JoinedThreads,
    watched: [Option<Arc<AtomicBool>>; 4],
}

impl WorkerThreads {
    pub(crate) fn watch(&mut self, role: Role, failure: Arc<AtomicBool>) {
        self.watched[role as usize] = Some(failure);
    }
    pub(crate) fn absorb(&mut self, mut other: Self) {
        assert_eq!(
            self.result.started & other.result.started,
            0,
            "each auxiliary role starts once"
        );
        for (index, slot) in other.threads.iter_mut().enumerate() {
            // Check before taking so a rejected incoming owner still joins
            // its own handles while unwinding, rather than detaching them.
            assert!(self.threads[index].is_none() || slot.is_none());
            if let Some(thread) = slot.take() {
                self.threads[index] = Some(thread);
            }
        }
        for (index, fault) in other.watched.iter_mut().enumerate() {
            if fault.is_some() {
                self.watched[index] = fault.take();
            }
        }
        self.result.started |= other.result.started;
        self.result.joined |= other.result.joined;
        self.result.panicked |= other.result.panicked;
        self.result.failed |= other.result.failed;
    }
    pub(crate) fn register(
        &mut self,
        role: Role,
        join: JoinHandle<io::Result<()>>,
        stop: impl FnOnce() -> io::Result<()> + Send + 'static,
    ) {
        let index = role as usize;
        // Keep incoming custody through invariant checks too. A repeated
        // registration cannot detach the newly started thread on panic.
        let mut incoming = Self::default();
        incoming.threads[index] = Some(Thread {
            join,
            stop: Box::new(stop),
        });
        incoming.result.started = 1 << index;
        assert_eq!(self.result.started & (1 << index), 0);
        self.result.started |= 1 << index;
        self.threads[index] = incoming.threads[index].take();
    }

    pub(crate) fn stop_and_join(&mut self) -> JoinedThreads {
        // Fixed role order settles nonce producers before the auth reader,
        // then preserves the writable half for the releaser's final flush.
        for (index, thread) in self.threads.iter_mut().enumerate() {
            let Some(Thread { join, stop }) = thread.take() else {
                continue;
            };
            let bit = 1 << index;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(stop)) {
                Ok(Ok(())) => {}
                Ok(Err(_)) => self.result.failed |= bit,
                Err(payload) => {
                    self.result.failed |= bit;
                    discard_panic(payload);
                }
            }
            match join.join() {
                Ok(result) => {
                    if result.is_err() {
                        self.result.failed |= bit;
                    }
                }
                Err(payload) => {
                    self.result.panicked |= bit;
                    // Never abandon sibling joins because a panic payload has
                    // a panicking destructor. A second panic is unrecoverable.
                    discard_panic(payload);
                }
            }
            self.result.joined |= bit;
        }
        for (index, failure) in self.watched.iter().enumerate() {
            if failure
                .as_ref()
                .is_some_and(|failure| failure.load(Ordering::SeqCst))
            {
                self.result.failed |= 1 << index;
            }
        }
        self.result
    }
}

impl Drop for WorkerThreads {
    fn drop(&mut self) {
        // This fallback physically joins started threads, but is never a
        // manager-drain/required-producer-settlement receipt.
        self.stop_and_join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Mutex};

    #[test]
    fn auxiliary40_stop_panic_does_not_discard_joins_or_later_stop_controls() {
        let mut threads = WorkerThreads::default();
        threads.register(Role::NoncePool, std::thread::spawn(|| Ok(())), || {
            panic!("controlled stop panic")
        });
        let (stop, seen) = mpsc::channel();
        threads.register(Role::AuthReader, std::thread::spawn(|| Ok(())), move || {
            stop.send(()).unwrap();
            Ok(())
        });
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| threads.stop_and_join()));
        drop(threads);
        seen.recv().unwrap();
        assert!(
            result.is_ok(),
            "stop panic abandoned its own handle and skipped remaining owners"
        );
        let result = result.unwrap();
        assert_eq!(result.joined, 0b0101);
        assert_ne!(result.failed & 1, 0);
    }

    #[test]
    fn auxiliary40_late_required_producer_fault_remains_after_actual_joins() {
        let mut threads = WorkerThreads::default();
        let failure = Arc::new(AtomicBool::new(false));
        threads.watch(Role::TellReleaser, failure.clone());
        threads.register(Role::TellReleaser, std::thread::spawn(|| Ok(())), || Ok(()));
        assert_eq!(threads.stop_and_join().joined, 0b1000);
        failure.store(true, Ordering::SeqCst);
        assert_eq!(
            threads.stop_and_join().failed,
            0b1000,
            "a late required tell cannot be hidden by earlier physical joins"
        );
    }

    #[test]
    fn auxiliary40_held_thread_prevents_join_receipt() {
        let mut threads = WorkerThreads::default();
        let (entered, entry) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let (stopped, stop_seen) = mpsc::channel();
        let (done, completion) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            entered.send(()).unwrap();
            held.recv().unwrap();
            Ok(())
        });
        entry.recv().unwrap();
        threads.register(Role::ChannelReader, handle, move || {
            stopped.send(()).unwrap();
            Ok(())
        });
        std::thread::scope(|scope| {
            let joining = scope.spawn(move || {
                let result = threads.stop_and_join();
                done.send(result).unwrap();
                // The RED stub's fallback still owns and actually joins the
                // thread after release; assertions run only after both join.
            });
            stop_seen.recv().unwrap();
            let early = completion.try_recv().ok();
            release.send(()).unwrap();
            joining.join().unwrap();
            let result = early.unwrap_or_else(|| completion.recv().unwrap());
            assert!(early.is_none(), "receipt preceded actual held-thread join");
            assert_eq!(result.joined, 1 << Role::ChannelReader as usize);
        });
    }

    #[test]
    fn auxiliary40_partial_start_and_panic_still_join_every_started_sibling() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut threads = WorkerThreads::default();
        for role in [Role::NoncePool, Role::ChannelReader, Role::AuthReader] {
            let events = observed.clone();
            let (release, held) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                held.recv().unwrap();
                assert_ne!(role, Role::ChannelReader, "controlled auxiliary panic");
                Ok(())
            });
            threads.register(role, handle, move || {
                events.lock().unwrap().push(role);
                release.send(()).unwrap();
                Ok(())
            });
        }
        // A failed fourth spawn creates no fourth handle. Previously started
        // siblings remain owned and must all be stopped/joined despite panic.
        let result = threads.stop_and_join();
        drop(threads); // RED fallback actually joins every owned thread
        assert_eq!(result.started, 0b111);
        assert_eq!(result.joined, 0b111);
        assert_eq!(result.panicked, 1 << Role::ChannelReader as usize);
        assert_eq!(
            *observed.lock().unwrap(),
            [Role::NoncePool, Role::ChannelReader, Role::AuthReader]
        );
    }
}
