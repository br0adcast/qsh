//! The requests the helper cannot finish on the spot.
//!
//! The helper is single-threaded and serves every session on the machine
//! from one loop, so a wait inside a request handler is an outage for
//! everybody: while the channel handler waited for a channel's child to report
//! its own startup, no other session's channel was opened, no nonce was
//! issued, and nothing was reaped -- and the worker, whose nonce request
//! runs on its router task, stood still with it (slice 2b's final review,
//! finding D1).
//!
//! Whatever has to wait for a CHILD therefore leaves the handler as a
//! [`Pending`] entry instead: its report pipe joins the loop's own `poll`
//! set, beside the two seams, and the loop comes back to it when the pipe
//! speaks or when its deadline passes. Nothing in this module blocks, and
//! nothing here decides anything -- what a verdict MEANS is the loop's
//! business (`server`'s `finish_pending`); this table only holds the
//! waiting and answers "which of these is ready" and "which has run out of
//! time".
//!
//! A VERIFICATION is keyed by the RAW descriptor number of its report
//! pipe, and the loop asks for one back by that number after `poll`
//! ([`PendingTable::take_ready`]). That is deliberate: the loop builds its
//! `PollFd` array itself, through `BorrowedFd::borrow_raw`, so the array
//! never borrows this table -- and the table can therefore be mutated in
//! the very pass whose array was built from it, with no borrow fight to
//! work around.
//!
//! A CHANNEL start has no pipe of its own to be keyed by: since task 7 its
//! shell is forked by the login's MONITOR, whose one seam carries the
//! startup of every channel of that login, so the loop comes back to such
//! an entry by CHANNEL ID, when that seam says something about it
//! ([`PendingTable::take_channel`]). Both kinds share the table all the
//! same: the deadline sweep, the cancellations and the question of which
//! logins still have something in flight are the same questions for both,
//! and answering them over two tables is how one of them gets forgotten.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use nix::unistd::{Pid, Uid};
use transport::LoginId;

use super::protocol::{AuthRequestId, ChannelId};

/// A request the helper cannot finish on the spot: somebody else's process
/// is working on it -- a child of the helper's own, or a login's monitor --
/// and what it will say is in the loop's poll set. Nothing here blocks; the
/// loop comes back when that process speaks or when the deadline passes.
pub(super) struct Pending {
    /// When the helper gives up. Absolute rather than a budget, so the loop
    /// can ask for the nearest one across the whole table without knowing
    /// what each entry is for.
    pub(super) deadline: Instant,
    /// What the verdict, when it comes, is a verdict ABOUT -- everything
    /// the answer needs that does not come back with it.
    pub(super) what: PendingWhat,
}

/// How the table names one entry, and so how the loop asks for it back.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum PendingKey {
    /// A verification, by the descriptor number of its child's report pipe
    /// -- the number the loop polls for it.
    Report(RawFd),
    /// A channel start, by the channel id the worker asked for. Its
    /// monitor's seam is polled once for the whole login, so the number
    /// that woke the loop does not name the entry; the event read off it
    /// does.
    Channel(ChannelId),
}

/// The kinds of request that can be left waiting on a child. Task 4 adds
/// `Verify` here, whose child does the account lookup, the key file and the
/// signature -- the other three things in this helper that can block for as
/// long as somebody else's file system feels like.
pub(super) enum PendingWhat {
    /// A `Request::Open` whose shell the login's monitor has been asked to
    /// fork, and which has not yet said whether its `exec` took.
    Channel {
        /// The channel id the worker asked for, already reserved in
        /// `LoopState::live` as `ChannelSlot::Starting` -- see that enum's
        /// docs for why the reservation cannot wait for this verdict.
        id: ChannelId,
        /// The master side of the channel's terminal, held here rather than
        /// handed over at once: it travels with the `Opened` answer, which
        /// only the verdict below can produce, and closing it early would
        /// hang up the terminal under a child that is still starting.
        master: OwnedFd,
        /// The login this channel belongs to, so the verdict can put the id
        /// in that login's open set (`LoginState::channels`), and so
        /// `Request::LoginEnded` can find this start to cancel it.
        login: LoginId,
        /// The account the channel is for. Only ever logged: every decision
        /// about whose channel this is was made before the fork, and a uid
        /// in the log line is what lets an operator line a refused channel
        /// up with the account that saw it fail.
        uid: Uid,
        /// Whether a `Request::Close` has already asked for this channel
        /// while it was still starting.
        ///
        /// The monitor's `Started` cannot be trusted in that case: `Close`
        /// sends `SIGHUP`, which ends a shell that has not exec'd yet, and
        /// the dying shell's report pipe reaches end-of-file with no data
        /// -- byte-identical to the end-of-file a SUCCESSFUL `execve`
        /// produces, and the monitor reads it the same way. Without this
        /// flag the helper would answer `Opened`, with a terminal, for a
        /// corpse.
        cancelled: bool,
    },
    /// A `Request::Verify` whose proof a child of its own is checking: the
    /// account lookup (a name service with no deadline), that account's
    /// `authorized_keys` (a home directory that may never answer), and a
    /// signature over bytes an attacker chose. None of the three is
    /// something the single-threaded loop may wait for.
    Verify {
        /// The read end of the child's report pipe. Owned here, so the
        /// number [`PendingTable`] keys this entry by cannot be handed out
        /// to anything else while the entry is on file, and is closed
        /// exactly when the entry leaves the table.
        report: OwnedFd,
        /// The child the loop is waiting on -- what a timeout kills and
        /// what either failure hands to `LoopState::orphans` to be reaped.
        child: Pid,
        /// The number the answer must carry back on the AUTHENTICATION
        /// seam. Every answer there is matched to its question by this
        /// number (see `protocol::AuthRequest`), so a verdict that lost it
        /// could admit one client under another client's proof.
        id: AuthRequestId,
        /// The account name the proof claimed -- for the helper's own log
        /// line, and never for the wire.
        ///
        /// As the worker named it and this helper bounded it
        /// (`server::sanitized_login_name`), for the same reason `rhost`
        /// below is bounded: it is written into a ROOT process's log, on a
        /// path reachable before anything has authenticated, and a newline
        /// in it would forge a line of that log.
        login: String,
        /// The login this proof is for. Carried across the wait because
        /// the verdict is where that login's entry gets CREATED
        /// (`ensure_login` -- the only place one is), and it cannot be
        /// looked up again afterwards because it does not exist yet.
        ///
        /// Without this field the entry would once more wait for a first
        /// `Open`, and task 2's availability fix would revert in silence:
        /// a session that has proved itself but not yet opened anything
        /// would lose its account's verification the moment some OTHER
        /// login of that account ended. See `Request::Verify`'s own docs.
        login_id: LoginId,
        /// Where the client was, as the worker named it and this helper
        /// bounded it (`server::sanitized_rhost`). Carried across the wait
        /// for the same reason `login_id` is: the login entry it belongs to
        /// is created ON the verdict, and there is nothing to look it up
        /// from until then.
        rhost: String,
    },
}

/// Every request the helper is waiting on somebody else's process for, by
/// the report pipe's descriptor number (a verification) or by the channel
/// id (a channel start) -- see [`PendingKey`].
#[derive(Default)]
pub(super) struct PendingTable {
    entries: HashMap<PendingKey, Pending>,
}

impl PendingTable {
    /// Take `pending` in, under the key its own kind decides.
    ///
    /// A report pipe's number already in the table would mean the kernel
    /// handed out a descriptor this process has not closed. It cannot: the
    /// table owns every report pipe it holds (`PendingWhat::Verify`'s
    /// `report` is an `OwnedFd`) and closes one only as the entry leaves,
    /// so no live entry's number is available for a later `pipe2` to be
    /// given. A channel id already in the table cannot happen either: an
    /// `Open` naming an id already in `LoopState::live` is refused before
    /// anything is started for it, and an id stays there for at least as
    /// long as this entry does.
    pub(super) fn insert(&mut self, pending: Pending) {
        let key = match &pending.what {
            PendingWhat::Channel { id, .. } => PendingKey::Channel(*id),
            PendingWhat::Verify { report, .. } => PendingKey::Report(report.as_raw_fd()),
        };
        self.entries.insert(key, pending);
    }

    /// The descriptor numbers the loop must add to its `poll` set. Plain
    /// numbers, not borrows -- see this module's docs for why that is the
    /// point rather than a shortcut. A channel start contributes none: what
    /// the loop polls for it is its login's monitor seam, which the loop
    /// holds itself.
    pub(super) fn poll_fds(&self) -> Vec<RawFd> {
        self.entries
            .keys()
            .filter_map(|key| match key {
                PendingKey::Report(fd) => Some(*fd),
                PendingKey::Channel(_) => None,
            })
            .collect()
    }

    /// The entry `fd` names, removed from the table. `None` for a number
    /// this table does not hold, which is how a loop pass that names the
    /// same number twice -- or one that names an entry some earlier step of
    /// the same pass already finished -- costs nothing.
    pub(super) fn take_ready(&mut self, fd: RawFd) -> Option<Pending> {
        self.entries.remove(&PendingKey::Report(fd))
    }

    /// The channel start `id` names, removed from the table -- what a
    /// monitor's `Started`/`Failed` for that channel is applied to. `None`
    /// for a channel this table is not waiting on, which is what a monitor
    /// naming a channel the helper has already given up on costs.
    pub(super) fn take_channel(&mut self, id: ChannelId) -> Option<Pending> {
        self.entries.remove(&PendingKey::Channel(id))
    }

    /// Every entry whose deadline `now` has reached, removed from the
    /// table. Inclusive at the boundary, the way `sweep_expired_nonces` is:
    /// an entry exactly at its deadline has had its whole budget.
    pub(super) fn take_expired(&mut self, now: Instant) -> Vec<Pending> {
        let expired: Vec<PendingKey> = self
            .entries
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key))
            .collect()
    }

    /// Whether any request still waiting on a child belongs to `login`.
    ///
    /// A channel between its fork and its verdict is NOT in
    /// `LoginState::channels` yet -- that insert happens when the child
    /// reports -- so an empty set does not mean the login has nothing. See
    /// `sweep_expired_logins`, the one caller, for what an entry dropped
    /// under a start actually costs.
    ///
    /// The entry being finished is never among these: `take_ready`,
    /// `take_channel` and `take_expired` each remove it before its verdict
    /// is applied, so a request can never see itself here and block its own
    /// cleanup.
    pub(super) fn holds_login(&self, login: &LoginId) -> bool {
        self.entries.values().any(|pending| match &pending.what {
            PendingWhat::Channel {
                login: waiting_for, ..
            } => waiting_for == login,
            // A verification in flight holds no login entry: there is
            // nothing on file for it yet, because its entry is created ON
            // the verdict. So there is nothing here for a remover to drop
            // out from under, which is the only thing this question asks.
            PendingWhat::Verify { .. } => false,
        })
    }

    /// Mark the request waiting on channel `id` as cancelled, and say
    /// whether there was one -- what `Request::Close` does to a channel that
    /// has not reported its startup yet. See `PendingWhat::Channel`'s
    /// `cancelled` for why the pipe alone cannot say this.
    pub(super) fn cancel_channel(&mut self, id: ChannelId) -> bool {
        for pending in self.entries.values_mut() {
            match &mut pending.what {
                PendingWhat::Channel {
                    id: waiting_for,
                    cancelled,
                    ..
                } if *waiting_for == id => {
                    *cancelled = true;
                    return true;
                }
                PendingWhat::Channel { .. } => {}
                // `Request::Close` names a CHANNEL id; a verification has
                // none and cannot be closed by one.
                PendingWhat::Verify { .. } => {}
            }
        }
        false
    }

    /// Mark every request waiting on a start of `login` as cancelled, and
    /// say how many there were -- what `Request::LoginEnded` does before it
    /// removes that login's entry.
    ///
    /// This is what lets every remover of a login entry obey one rule
    /// rather than two. `sweep_expired_logins` ASKS whether a start of the
    /// login is in flight and declines to remove while one is; `LoginEnded`
    /// cannot decline -- nobody re-sends it, so a removal deferred is a
    /// removal lost -- so it MAKES the answer no instead. The starts it
    /// cancels are refused and killed by their own verdicts, exactly as a
    /// `Close` during startup is (see `PendingWhat::Channel`'s `cancelled`,
    /// and `finish_pending`).
    pub(super) fn cancel_login(&mut self, login: &LoginId) -> usize {
        let mut cancelled_now = 0;
        for pending in self.entries.values_mut() {
            match &mut pending.what {
                PendingWhat::Channel {
                    login: waiting_for,
                    cancelled,
                    ..
                } if waiting_for == login => {
                    *cancelled = true;
                    cancelled_now += 1;
                }
                PendingWhat::Channel { .. } => {}
                // A verification is deliberately NOT cancelled here. What
                // makes a cancelled channel necessary is that its child's
                // end-of-file is ambiguous -- byte-identical to a
                // successful `exec` -- so only a flag can tell the two
                // apart. A verdict is never ambiguous: an incomplete one
                // is a refusal, always. And a proof that verifies after
                // its login ended is a client presenting fresh
                // credentials, which may legitimately open that login
                // again; the entry it recreates starts provisional and is
                // swept at `LOGIN_GRACE` if nothing comes of it.
                PendingWhat::Verify { .. } => {}
            }
        }
        cancelled_now
    }

    /// How many proofs are being checked right now -- what
    /// `server::MAX_VERIFYING` bounds.
    ///
    /// Counted on demand rather than kept in a counter beside the table: a
    /// second piece of state would have to be held in step with every
    /// insert and with all three ways an entry leaves (`take_ready`,
    /// `take_expired`, and the table being dropped), and this table never
    /// holds more than a few dozen entries.
    pub(super) fn verifying(&self) -> usize {
        self.entries
            .values()
            .filter(|pending| matches!(pending.what, PendingWhat::Verify { .. }))
            .count()
    }

    /// Whether the helper is waiting on anything at all -- what a test
    /// that settles "everything pending" asks, now that a channel start
    /// contributes no descriptor to [`PendingTable::poll_fds`] and an empty
    /// poll set no longer means an empty table.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How long until the SOONEST deadline in the table, or `None` when
    /// nothing is waiting -- what bounds how long the loop may sleep in
    /// `poll`, so that a child that says nothing at all is still given up on
    /// at its own deadline rather than at some later entry's.
    pub(super) fn nearest_deadline(&self, now: Instant) -> Option<Duration> {
        self.entries
            .values()
            .map(|pending| pending.deadline.saturating_duration_since(now))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel start for the tests below: the channel id it is keyed by,
    /// a stand-in for the terminal it is holding, and the deadline under
    /// test.
    fn pending_at(id: ChannelId, deadline: Instant) -> Pending {
        Pending {
            deadline,
            what: PendingWhat::Channel {
                id,
                master: nix::unistd::pipe().expect("a stand-in for the terminal").0,
                login: [0u8; 16],
                uid: Uid::current(),
                cancelled: false,
            },
        }
    }

    /// The boundary is inclusive: an entry exactly at its deadline has had
    /// its whole budget and is expired, while one a moment short of it is
    /// not. A pure test over synthetic instants, the way
    /// `sweep_expired_nonces_uses_an_inclusive_boundary` is -- no real wait.
    #[test]
    fn take_expired_is_inclusive_at_the_boundary() {
        let now = Instant::now();
        let mut table = PendingTable::default();
        table.insert(pending_at(1, now));
        table.insert(pending_at(2, now + Duration::from_millis(1)));

        let expired = table.take_expired(now);

        assert_eq!(
            expired.len(),
            1,
            "exactly the entry at its deadline must expire"
        );
        assert!(
            table.take_channel(1).is_none(),
            "an expired entry must be gone from the table, not merely reported"
        );
        assert!(
            table.take_channel(2).is_some(),
            "an entry a moment short of its deadline must stay"
        );
    }

    /// A channel start is asked for back by its CHANNEL ID, not by a
    /// descriptor number: its shell is the monitor's child, and the seam
    /// that says what became of it is shared by every channel of that
    /// login. It therefore adds nothing to the loop's poll set either --
    /// the loop polls that one seam itself.
    #[test]
    fn a_channel_start_is_keyed_by_its_id_and_polled_for_by_nothing() {
        let mut table = PendingTable::default();
        table.insert(pending_at(7, Instant::now() + Duration::from_secs(1)));

        assert!(
            table.poll_fds().is_empty(),
            "a channel start has no report pipe of its own to poll"
        );
        assert!(
            table.take_channel(8).is_none(),
            "another channel's id must name nothing"
        );
        assert!(
            table.take_channel(7).is_some(),
            "its own id must name it, which is how a monitor's word about it is applied"
        );
    }

    /// A verification in flight holds NO login entry: its entry is created
    /// ON the verdict, so there is nothing here for a remover to drop out
    /// from under. Answering `true` instead would pin EVERY login open for
    /// as long as any proof is being checked -- the answer does not depend
    /// on which login is asked about -- so `sweep_expired_logins` would
    /// never expire one while a proof is in flight, leaving accounts in
    /// `verified` longer than they belong there.
    #[test]
    fn a_pending_verification_holds_no_login() {
        let (report, write) = nix::unistd::pipe().expect("a pipe for the report");
        drop(write);
        let login = [7u8; 16];
        let mut table = PendingTable::default();
        table.insert(Pending {
            deadline: Instant::now() + Duration::from_secs(1),
            what: PendingWhat::Verify {
                report,
                child: Pid::from_raw(999_999),
                id: 1,
                login: "alice".to_string(),
                login_id: login,
                rhost: String::new(),
            },
        });

        assert!(
            !table.holds_login(&login),
            "a verification has no login entry on file, so it can hold none open"
        );
        assert_eq!(
            table.verifying(),
            1,
            "and it is still counted as a verification in flight, which is what caps it"
        );
    }

    /// Only verifications count against `MAX_VERIFYING`: a channel that is
    /// still starting must not, or enough slow channel starts by one account
    /// would refuse every other account's login.
    #[test]
    fn a_starting_channel_is_not_a_verification() {
        let mut table = PendingTable::default();
        table.insert(pending_at(1, Instant::now() + Duration::from_secs(1)));
        assert_eq!(
            table.verifying(),
            0,
            "a channel start in flight must not count as a verification"
        );
    }

    /// The loop sleeps no longer than the SOONEST deadline, not the
    /// furthest: a table answering with the furthest would let the helper
    /// sleep straight past a child it has already given up on.
    #[test]
    fn nearest_deadline_is_the_soonest_one() {
        let now = Instant::now();
        let mut table = PendingTable::default();
        assert_eq!(
            table.nearest_deadline(now),
            None,
            "an empty table bounds nothing"
        );

        table.insert(pending_at(1, now + Duration::from_millis(500)));
        table.insert(pending_at(2, now + Duration::from_millis(50)));
        table.insert(pending_at(3, now + Duration::from_millis(900)));

        assert_eq!(
            table.nearest_deadline(now),
            Some(Duration::from_millis(50)),
            "the loop must wake for the first deadline, not the last"
        );
        assert_eq!(
            table.nearest_deadline(now + Duration::from_secs(10)),
            Some(Duration::ZERO),
            "a deadline already past is zero, never a wrapped-around eternity"
        );
    }
}
