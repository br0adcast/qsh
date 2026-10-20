//! What the worker asks the helper for, and what it answers.
//!
//! Encoded as one JSON object per datagram. The socket is `SOCK_SEQPACKET`,
//! so message boundaries come from the kernel and there is no framing to get
//! wrong. JSON rather than a hand-rolled binary encoding because the message
//! rate is one per channel, and a well-tested parser beats one of our own on
//! the privileged side of the seam; what the design forbids there is a SHELL
//! grammar -- a command line the privileged helper would have to split into
//! words itself. So [`Request::Open`] carries the command WHOLE and unsplit,
//! and the account's own shell parses it (`<shell> -c <command>`), exactly
//! as under `sshd` -- which is also what keeps a confining shell
//! (`nologin`, `git-shell`, `rbash`) in charge of what it may do.
//!
//! Every message is capped at [`MAX_MESSAGE_LEN`]: the helper is the
//! privileged end, and an unbounded message is an unbounded allocation there.
//!
//! Two seams carry these messages, each its own socket pair (see
//! `helper::split_and_run`):
//! - the CHANNEL seam carries bare [`Request::Open`]/[`Request::Close`] and
//!   their outcomes, installed `Exited` notices, and independent cleanup receipts;
//! - the AUTHENTICATION seam carries [`Request::Nonce`],
//!   [`Request::ReleaseNonce`] and [`Request::Verify`], each wrapped in an
//!   [`AuthRequest`] and answered in an [`AuthResponse`] carrying the same
//!   number, so an answer can never be taken for the answer to a different
//!   request.
//!
//! Each seam drops the other's requests unanswered -- see
//! `helper::server`'s loop for why.
//!
//! A THIRD seam, of the same shape and with the same codec, runs between
//! the helper and each login's monitor (`helper::monitor`), and carries
//! [`MonitorRequest`] and [`MonitorEvent`] -- a separate pair of types, not
//! more arms on the two above, because nothing a worker can send may ever
//! be honoured as an instruction to a monitor, and nothing a monitor says
//! may ever be taken for an answer to a worker's request.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use transport::{LoginId, AUTH_NONCE_LEN};

/// The largest message either side will encode or accept.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024;

/// Identifies one channel for the life of the connection between the two
/// processes. Chosen by the worker in strictly increasing send order, never
/// reused or wrapped, and echoed by the helper.
pub type ChannelId = u64;

/// Numbers one request on the authentication seam. Chosen by the worker,
/// strictly increasing for the life of the connection, echoed by the helper
/// in its answer.
pub type AuthRequestId = u64;

/// A single-use handshake nonce, the same shape `transport::AUTH_NONCE_LEN`
/// pins on the wire -- kept as a type alias here rather than a bare `[u8; 16]`
/// so a change to that constant cannot silently drift the two apart.
pub type Nonce = [u8; AUTH_NONCE_LEN];

/// What the worker asks for.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Open a pseudo-terminal of `cols` x `rows`, run a program in it, and
    /// hand the master side back.
    Open {
        id: ChannelId,
        /// The account the channel is for: the uid of the session that asks
        /// for it, as `Response::Verified` named it when that session
        /// logged in. The helper refuses a uid it has not verified itself --
        /// the worker saying "this is alice's session" proves nothing.
        uid: u32,
        /// The canonical account name returned by `Response::Verified`,
        /// carried unchanged from the session's principal. UID alone cannot
        /// distinguish account aliases with different home, shell or PAM policy.
        /// Both UID and name must match this login's immutable binding.
        name: String,
        /// Which LOGIN this channel belongs to -- the router's own token for
        /// the device (`transport::LoginId`), stable across a warm reattach
        /// even though the session id is not. The login must already be on
        /// file with the helper -- only a successful [`Request::Verify`]
        /// for it puts it there -- and an `Open` never puts it there itself:
        /// one for a login that has ended, expired, or never proved anything
        /// is refused. A login belongs to exactly one account for its whole
        /// life: the helper also refuses an `Open` that names a different uid
        /// or canonical account name for the login. A PAM session is keyed by
        /// this login, rather than by any one channel or connection.
        login: LoginId,
        cols: u16,
        rows: u16,
        /// The client's terminal type, or `None` when it announced nothing.
        term: Option<String>,
        /// Kernel echo on the pseudo-terminal. Off for a tmux control-mode
        /// client, which must not be shown its own writes.
        echo: bool,
        /// Run the account's login shell rather than a command -- taken by
        /// the HELPER from passwd, as it verified the account (see
        /// `helper::server::login_shell`), never from the worker: the worker
        /// does not know, and does not share, the account this channel's
        /// process runs as. `true` means `command` is ignored (and sent
        /// empty).
        shell: bool,
        /// The command line, forwarded WHOLE and unparsed, the way `sshd`
        /// hands it to a login: the helper runs it as `<account shell> -c
        /// <command>`, so the account's own shell -- `nologin`, `git-shell`,
        /// `rbash` and the like included -- decides what it may do, exactly
        /// as under `sshd`. Valid UTF-8 (the worker checks). Ignored when
        /// `shell` is `true`.
        command: String,
    },
    /// The channel is gone on the worker's side; take the process down.
    Close { id: ChannelId },
    /// Ask for a fresh, single-use nonce for a handshake the worker is
    /// about to accept. Answered with [`Response::Nonce`], or
    /// [`Response::NonceUnavailable`] if the helper already has as many
    /// outstanding as it will hold at once.
    Nonce,
    /// Give up a nonce that was issued but will never be spent (a refused
    /// admission, a discarded retransmit, an allowlist accept, a probation
    /// that ended without proof). Removes it from the table if present; an
    /// unknown nonce (already spent, already expired, or never issued by
    /// this helper) is a no-op. **No response is sent** -- the worker must
    /// never wait on the helper for housekeeping.
    ReleaseNonce { nonce: Nonce },
    /// Ask the helper to verify a client's authentication proof itself --
    /// never trust the worker's own say-so about who logged in, because a
    /// taken-over worker's claim must not be believed. Answered with
    /// [`Response::Verified`] or [`Response::Refused`].
    Verify {
        /// The account the client claims, under the signature -- so nothing
        /// standing between the client and `getpwnam`, including a worker
        /// that has been taken over, can change it.
        login: String,
        /// The client's SSH public key, wire-encoded -- the same bytes that
        /// sit base64-encoded in `authorized_keys`.
        public_key: Vec<u8>,
        /// The SSH signature blob over `qsh-auth-v2 || handshake_hash ||
        /// nonce || login`.
        signature: Vec<u8>,
        /// This session's handshake hash, under the signature.
        handshake_hash: [u8; 32],
        /// The nonce this same helper issued for this handshake, via
        /// [`Request::Nonce`] -- also under the signature.
        nonce: Nonce,
        /// Which LOGIN this proof is for -- the router's own token for the
        /// device (`transport::LoginId`), the same one a later
        /// `Request::Open` for this account will carry. Named `login_id`
        /// rather than `login` (already taken above by the claimed account
        /// name) to keep the two apart in this one message. On success the
        /// helper creates this login's entry right away, tied to the
        /// verified account -- this is the only request that creates one,
        /// and every `Request::Open` for the login needs it: an account that
        /// has proved itself but not yet opened a channel must still have
        /// something on file for `Request::LoginEnded` to find, or it can be
        /// forgotten out from under a session that simply hasn't opened
        /// anything yet. Refused past `MAX_LOGINS`, or if this token already
        /// names a different account. A token whose login has ended is
        /// admitted again by a fresh proof like any other.
        ///
        /// The entry starts PROVISIONAL: the helper drops it on its own if
        /// no `Request::Open` ever opens a channel under it within its own
        /// grace period (`server::LOGIN_GRACE`). A proof that verifies and
        /// then goes nowhere -- the worker's session caps refusing the
        /// admission, a client that vanishes, a handshake that fails
        /// afterwards, a lost datagram -- can only be reported as ended by
        /// the worker for the FIRST of those; the grace period is what
        /// covers all the rest, so the privileged process bounds its own
        /// table rather than trusting the worker to be correct.
        login_id: LoginId,
        /// Where the client was when it logged in -- the source address the
        /// worker saw (`transport::probation`), kept with the login and
        /// logged as a full endpoint. The monitor gives `PAM_RHOST` only
        /// its numeric IP, without the port or IPv6 scope. Invalid or
        /// empty origins refuse the remote PAM transaction before it starts.
        ///
        /// **Its truth is never checked.** The worker chooses
        /// it, and the worker is the process this whole split exists to
        /// distrust: a taken-over one can name any address it likes. So a
        /// PAM module that decides by `PAM_RHOST` (`pam_access`,
        /// `pam_rhosts`) decides, in the system mode, on the word of a
        /// process nobody believes, and an administrator who adds such a
        /// module has to know it. Dropping the value instead would not be
        /// safer: a login with no address at all looks local to
        /// `pam_access`, which as a rule loosens its rules rather than
        /// tightening them.
        ///
        /// Bounded and printable-ASCII-only all the same (see
        /// `server::sanitized_rhost`): it reaches a root process's tables
        /// and, later, its log, and neither may be grown or scribbled on by
        /// a worker that has been taken over. Anything else becomes the
        /// empty string, which is also what a login whose address is
        /// unknown carries.
        rhost: String,
    },
    /// A login is over for good: the transport router's entry for it is
    /// gone (a graceful close, GC past retention, or an eviction -- see
    /// `transport::session_manager::Router::forget_backend`), not merely
    /// disconnected for now. The helper forgets that login, and forgets the
    /// account it belonged to once no other login of that account is still
    /// on file -- the threat model promises only whoever is connected right
    /// now, not whoever ever connected. **No response is sent**, the same
    /// as [`Request::ReleaseNonce`]: the worker must never wait on the
    /// helper for housekeeping.
    LoginEnded { login: LoginId },
}

/// What the helper answers. `Exited` arrives unprompted, whenever a child
/// dies, so the worker must demultiplex replies by `id` rather than assume
/// the next message answers its last request.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Response {
    /// Exact terminal cleanup fact, independent of Open/Exit outcomes.
    CleanupComplete { id: ChannelId, kind: CleanupKind },
    /// The channel is open: the account's SHELL has exec'd, which is the
    /// moment the child's close-on-exec startup-report pipe reaches
    /// end-of-file (see `helper::server::read_startup_report`). It does NOT
    /// mean the command's own program is running yet -- a channel runs
    /// `<shell> -c <command>`, so anything the command names appears only
    /// once the shell in turn execs it. A test that looks for that program
    /// must wait for it, never assert on it the instant this arrives.
    ///
    /// This has always been what the answer means, in the personal mode and
    /// the system mode alike; it is written down here because three tests
    /// in this crate were built on its opposite and raced under load until
    /// task 3's fix round 1.
    ///
    /// The master file descriptor travels alongside this message, out of
    /// band -- see `super::channel`.
    Opened { id: ChannelId },
    /// The channel could not be opened. `reason` is shown to the user, so it
    /// is written in the language the daemon's other messages use.
    Failed { id: ChannelId, reason: String },
    /// The channel's process has exited.
    Exited { id: ChannelId, code: i32 },
    /// A login the worker knew has ended, and no `Open` naming it will
    /// ever succeed again.
    ///
    /// Unsolicited, like [`Response::Exited`]: it answers no request. The
    /// worker's own session for that login is now sterile -- it pings
    /// fine and every channel it asks for is refused -- so the worker ends
    /// it and lets the client reconnect and prove itself again, which is
    /// the only way back (the proof rides the handshake, and a session
    /// resumed after a roam does not present it again).
    ///
    /// Sent ONLY for logins the worker already knew, that is, for which it
    /// received a `Verified` of its own. It therefore tells a taken-over
    /// worker nothing it did not already know, and is no account
    /// enumerator -- which is why it may name the login at all, where
    /// `Failed` may not name its reason (see the module docs on
    /// `REFUSED_REASON`).
    ///
    /// That covers every entry the helper holds, PROVISIONAL ones included:
    /// `server::ensure_login` creates an entry out of a successful
    /// [`Request::Verify`] and out of nothing else, so "the helper had an
    /// entry" and "the worker was told about it" are the same fact. A
    /// narrower gate on "a channel has opened under it" would be silent for
    /// exactly the logins the helper's age sweep ends -- see
    /// `server::forget_login`. A token the helper never held is named to
    /// nobody.
    ///
    /// `incarnation` names WHICH life of that login ended -- the value this
    /// same login's [`Response::Verified`] carried. The worker's router
    /// drops a notice older than the incarnation its current session was
    /// admitted under: the two messages travel on separate seams, are read
    /// by separate threads on the worker's side, and meet in one unbiased
    /// `select!`, so nothing else orders them. See
    /// `server::LoginState::incarnation`.
    LoginEnded { login: LoginId, incarnation: u64 },
    /// A freshly issued, single-use nonce -- see [`Request::Nonce`].
    Nonce { nonce: Nonce },
    /// The helper already has as many nonces outstanding as it will hold at
    /// once, and refuses to mint another rather than evict one that might
    /// still be spent -- see the helper's own `MAX_OUTSTANDING_NONCES` for
    /// why.
    NonceUnavailable,
    /// The proof verified: the nonce was ours, unspent and unexpired, the
    /// login resolved and is permitted, the signature verifies, and the key
    /// is listed in that account's `authorized_keys`.
    Verified {
        /// The account's numeric id.
        uid: u32,
        /// Which life of this device's login the entry the helper just
        /// created (or found already there) is -- `server::LoopState`'s own
        /// counter, strictly increasing and never reused. It comes back on
        /// [`Response::LoginEnded`] when that entry ends, and the worker's
        /// router compares the two: a notice for an OLDER incarnation is
        /// about a login that has already been replaced, and acting on it
        /// would tear down the session the same device has since been
        /// given. A repeat proof under a token already on file -- which is
        /// what a warm reattach is -- reports the number that entry already
        /// has, not a new one.
        incarnation: u64,
        /// The account's login name, as `getpwnam` returned it -- not
        /// necessarily byte-identical to what the client claimed, though it
        /// always matches under case and normalization `getpwnam` itself
        /// applies.
        name: String,
        /// Short human-readable identity for the log -- the key's
        /// fingerprint, the same format the personal mode uses. Never
        /// anything secret.
        identity: String,
    },
    /// The proof did not verify, for any of the reasons `Request::Verify`'s
    /// docs list. `reason` is always the same fixed string, whichever check
    /// failed -- see `server::REFUSED_REASON`'s docs for why: naming the
    /// real reason here would hand the worker an account and key
    /// enumerator. The real reason goes to the helper's own log instead.
    Refused { reason: String },
}

/// What the helper asks a login's MONITOR to do (`helper::monitor`).
///
/// Only the helper ever sends one, over the socket pair it made before it
/// forked that monitor; nothing a worker sends is ever turned into one. The
/// monitor decides nothing about WHO a channel is for -- the account, the
/// login and the terminal were all settled by the helper before the fork
/// (`monitor::MonitorPlan`) -- so nothing here names an account or a uid.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MonitorRequest {
    /// Fork a shell for channel `id` on the terminal that travels with this
    /// message -- its SLAVE side, out of band, the way a channel's master
    /// travels back to the worker (see `super::channel`).
    ///
    /// Only what changes from channel to channel is here. In particular
    /// neither the size of the terminal nor whether it echoes: the helper
    /// opens the terminal itself, at the size the request asked for, before
    /// it forks or speaks to a monitor at all.
    Open {
        id: ChannelId,
        /// The client's terminal type, or `None` when it announced nothing
        /// -- the `TERM` of the shell's environment.
        term: Option<String>,
        /// Run the account's login shell rather than a command. `true`
        /// means `command` is ignored (and sent empty).
        shell: bool,
        /// The command line, whole and unparsed, for the account's own
        /// shell to run as `<shell> -c <command>` -- see
        /// [`Request::Open`]'s field of the same name.
        command: String,
    },
    /// The channel is over: end its shell. `SIGHUP` first, `SIGKILL` once
    /// the grace period has passed -- both the monitor's, since the shell
    /// is the monitor's child and no longer the helper's to signal.
    Close { id: ChannelId },
}

/// Trusted internal cleanup provenance; errors and disconnection are neither.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CleanupKind {
    NoChild,
    Reaped,
}

/// What a monitor tells the helper about the shells it was asked to fork.
///
/// Each names the channel it is about, because one monitor serves every
/// channel of its login and the helper must never take one channel's news
/// for another's. Exactly one of `Started`/`Failed` is sent per `Open`, and
/// an `Exited` only ever follows a `Started`: a channel whose start failed
/// has already been answered. CleanupComplete is a separate terminal fact:
/// Linux monitors prove Reaped only after native session-scope cleanup, startup
/// pipe retirement, and the reserved child's actual final wait. Legacy monitors
/// retain their direct-child meaning. Audited pre-fork failures prove NoChild;
/// neither an exit status nor disconnection proves either cleanup fact.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MonitorEvent {
    /// No shell was created, or the monitor completed its owned cleanup scope.
    CleanupComplete { id: ChannelId, kind: CleanupKind },
    /// The shell exec'd -- the same moment, and the same evidence (the
    /// startup-report pipe at end-of-file after a valid native session stage), that [`Response::Opened`]
    /// stands for.
    Started { id: ChannelId },
    /// The shell could not be started, and this is the `errno` that says
    /// why -- what the helper turns into the [`Response::Failed`] the
    /// worker sees. A plain `i32` rather than an `Errno`: this is a wire
    /// format, and a value the helper does not recognise must decode as
    /// itself rather than fail the whole message.
    Failed { id: ChannelId, errno: i32 },
    /// The shell exited, with this code -- signalled exits reported the way
    /// a shell reports them, as 128 plus the signal number.
    Exited { id: ChannelId, code: i32 },
    /// Login session setup failed before any shell was forked: the account
    /// or session stack refused, the transaction could not start, or group
    /// installation/capture failed. Any opened PAM session was torn down.
    ///
    /// Separate from [`MonitorEvent::Failed`], which carries an `errno` the
    /// helper names on the wire, because a refusal must reach the worker as
    /// the one shared `server::REFUSED_REASON` and nothing else: which
    /// check refused a login is exactly what a worker that has been taken
    /// over must not be able to enumerate. `why` is for the helper's own
    /// LOG -- it never goes on the wire -- and it comes over the seam
    /// rather than being written where it was found, because a monitor may
    /// not write to the log at all (see `helper::monitor`'s module docs).
    ///
    /// Bounded and printable-ASCII-only (`monitor::sanitized_detail`): it
    /// is written by PAM modules the administrator configured, and it ends
    /// up in a root process's log, where a newline would forge a second
    /// line.
    Refused { id: ChannelId, why: String },
    /// Something the login's PAM stack said as an ERROR while letting the
    /// login IN -- an optional module that failed, a warning about an
    /// expiring password. The session opened; this is the "something is
    /// wrong all the same" half.
    ///
    /// It goes to the helper's log and nowhere else. There is no
    /// interactive side to a channel while its session is being opened, so
    /// it cannot be shown to the person logging in, and a monitor may not
    /// write to the log itself (see `helper::monitor`'s module docs) -- so
    /// without this event it reaches nobody at all. Informational: nothing
    /// is refused, and the helper answers the channel exactly as it would
    /// have.
    ///
    /// Only the errors, never the `PAM_TEXT_INFO` chatter: forwarding
    /// "motd"-like text on every login would make a root process's log
    /// grow at the rate an administrator's module chooses. Bounded and
    /// printable-ASCII-only, for the same reason
    /// [`MonitorEvent::Refused`]'s `why` is.
    Noted { id: ChannelId, what: String },
    /// A signal the monitor could not deliver to its own child -- `EPERM`
    /// above all, which is what a service unit that stopped granting
    /// `CAP_KILL` (spec §8.3) looks like from in there.
    ///
    /// Reported rather than discarded because the monitor may not write to
    /// the log (see `helper::monitor`'s module docs), and because a
    /// `SIGHUP`-ignoring shell then never dies, never reports an exit, and
    /// pins its channel until the helper kills the whole monitor -- with
    /// nothing in the log to say why. Before this task the helper signalled
    /// a channel's process itself and said exactly this through
    /// `server::log_failed_kill`; the signals moved, and this is how the
    /// line gets back.
    ///
    /// `ESRCH` -- the shell exited between the lookup and the signal -- is
    /// ordinary and is never reported.
    SignalFailed {
        id: ChannelId,
        /// The signal number, as `nix::sys::signal::Signal` numbers them.
        signal: i32,
        /// Why it could not be delivered, as a raw `errno` -- a plain
        /// `i32` for the same reason [`MonitorEvent::Failed`]'s is.
        errno: i32,
    },
    /// The monitor completed its acquired PAM cleanup steps; neither child
    /// exit nor a channel receipt substitutes for this monitor-level evidence.
    SessionClosed {
        result: super::pam_completion::PamCompletion,
    },
}

/// A request on the authentication seam: a [`Request`] and the number the
/// helper's answer must carry back.
///
/// The number is what ties an answer to its question. Without it a worker
/// that stopped waiting for one answer -- it timed out -- would read that
/// late answer as the reply to its NEXT request, and a `Verified` for alice,
/// arriving in reply to somebody else's proof, would let that somebody in as
/// alice.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub id: AuthRequestId,
    pub body: Request,
}

/// The helper's answer on the authentication seam, carrying the number of
/// the [`AuthRequest`] it answers.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub id: AuthRequestId,
    pub body: Response,
}

/// Everything that can be wrong with a message.
#[derive(Debug)]
pub enum ProtocolError {
    /// Longer than [`MAX_MESSAGE_LEN`].
    TooLong { len: usize },
    /// Not a message at all.
    Malformed(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::TooLong { len } => {
                write!(
                    f,
                    "helper message of {len} bytes exceeds the {MAX_MESSAGE_LEN}-byte cap"
                )
            }
            ProtocolError::Malformed(why) => write!(f, "malformed helper message: {why}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Encode one message, refusing anything over the cap.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes =
        serde_json::to_vec(msg).map_err(|e| ProtocolError::Malformed(format!("encoding: {e}")))?;
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::TooLong { len: bytes.len() });
    }
    Ok(bytes)
}

/// Decode one message. The cap is checked BEFORE parsing, so an over-long
/// datagram costs nothing beyond the read that already happened.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::TooLong { len: bytes.len() });
    }
    // `one_line`: `serde_json` quotes what it could not match verbatim, so
    // this text is the sender's -- whoever logs it must not get a newline.
    serde_json::from_slice(bytes)
        .map_err(|e| ProtocolError::Malformed(crate::log::one_line(&e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips() {
        for req in [
            Request::Open {
                id: 7,
                uid: 1000,
                name: "alice".into(),
                login: [3u8; 16],
                cols: 80,
                rows: 24,
                term: Some("xterm-256color".to_string()),
                echo: true,
                shell: false,
                command: "vim /etc/hosts".to_string(),
            },
            Request::Close { id: 7 },
            Request::Nonce,
            Request::ReleaseNonce {
                nonce: [5u8; AUTH_NONCE_LEN],
            },
            Request::Verify {
                login: "alice".to_string(),
                public_key: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                handshake_hash: [7u8; 32],
                nonce: [8u8; AUTH_NONCE_LEN],
                login_id: [10u8; 16],
                rhost: "203.0.113.7:51234".to_string(),
            },
            Request::LoginEnded { login: [9u8; 16] },
        ] {
            let bytes = encode(&req).expect("encodes");
            assert_eq!(decode::<Request>(&bytes).expect("decodes"), req);
        }
    }

    #[test]
    fn an_open_without_an_account_name_is_not_a_valid_request() {
        let mut request = serde_json::json!({"Open": {
            "id": 1, "uid": 1000, "name": "alice", "login": vec![3; 16],
            "cols": 80, "rows": 24, "term": null, "echo": true,
            "shell": false, "command": "true"
        }});
        assert!(decode::<Request>(&serde_json::to_vec(&request).unwrap()).is_ok());
        request["Open"].as_object_mut().unwrap().remove("name");
        assert!(decode::<Request>(&serde_json::to_vec(&request).unwrap()).is_err());
    }

    #[test]
    fn a_response_round_trips() {
        for msg in [
            Response::Opened { id: 1 },
            Response::CleanupComplete {
                id: 1,
                kind: CleanupKind::NoChild,
            },
            Response::CleanupComplete {
                id: 2,
                kind: CleanupKind::Reaped,
            },
            Response::Failed {
                id: 2,
                reason: "no such file".to_string(),
            },
            Response::Exited { id: 3, code: 130 },
            Response::Nonce {
                nonce: [9u8; AUTH_NONCE_LEN],
            },
            Response::NonceUnavailable,
            Response::Verified {
                uid: 1000,
                name: "alice".to_string(),
                identity: "SHA256:abcdef".to_string(),
                incarnation: 0,
            },
            Response::Refused {
                reason: "authentication failed".to_string(),
            },
        ] {
            let bytes = encode(&msg).expect("encodes");
            assert_eq!(decode::<Response>(&bytes).expect("decodes"), msg);
        }
    }

    /// The monitor's own pair of messages crosses its own seam whole --
    /// the same codec the worker's do, and a type of its own at each end.
    #[test]
    fn the_monitor_messages_round_trip() {
        for request in [
            MonitorRequest::Open {
                id: 4,
                term: Some("xterm-256color".to_string()),
                shell: false,
                command: "vim /etc/hosts".to_string(),
            },
            MonitorRequest::Open {
                id: 5,
                term: None,
                shell: true,
                command: String::new(),
            },
            MonitorRequest::Close { id: 4 },
        ] {
            let bytes = encode(&request).expect("encodes");
            assert_eq!(decode::<MonitorRequest>(&bytes).expect("decodes"), request);
        }
        for event in [
            MonitorEvent::Started { id: 4 },
            MonitorEvent::CleanupComplete {
                id: 4,
                kind: CleanupKind::NoChild,
            },
            MonitorEvent::CleanupComplete {
                id: 5,
                kind: CleanupKind::Reaped,
            },
            MonitorEvent::Failed {
                id: 4,
                errno: nix::libc::ENOENT,
            },
            MonitorEvent::Exited { id: 4, code: 137 },
            MonitorEvent::SignalFailed {
                id: 4,
                signal: nix::libc::SIGKILL,
                errno: nix::libc::EPERM,
            },
        ] {
            let bytes = encode(&event).expect("encodes");
            assert_eq!(decode::<MonitorEvent>(&bytes).expect("decodes"), event);
        }
    }

    /// Both envelopes keep their number and their body across the wire.
    #[test]
    fn the_authentication_envelopes_round_trip() {
        let request = AuthRequest {
            id: 41,
            body: Request::Nonce,
        };
        let bytes = encode(&request).expect("encodes");
        assert_eq!(decode::<AuthRequest>(&bytes).expect("decodes"), request);

        let response = AuthResponse {
            id: 41,
            body: Response::Refused {
                reason: "authentication failed".to_string(),
            },
        };
        let bytes = encode(&response).expect("encodes");
        assert_eq!(decode::<AuthResponse>(&bytes).expect("decodes"), response);
    }

    /// The helper's input is bounded on purpose: it is the privileged side of
    /// the seam, and an unbounded message is an unbounded allocation there.
    #[test]
    fn an_over_long_message_is_refused_by_the_encoder() {
        let req = Request::Open {
            id: 1,
            uid: 1000,
            name: "alice".into(),
            login: [3u8; 16],
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: "x".repeat(MAX_MESSAGE_LEN),
        };
        assert!(matches!(encode(&req), Err(ProtocolError::TooLong { .. })));
    }

    #[test]
    fn an_over_long_message_is_refused_by_the_decoder() {
        let bytes = vec![b'x'; MAX_MESSAGE_LEN + 1];
        assert!(matches!(
            decode::<Request>(&bytes),
            Err(ProtocolError::TooLong { .. })
        ));
    }

    #[test]
    fn garbage_is_refused_rather_than_panicking() {
        assert!(matches!(
            decode::<Request>(b"not json at all"),
            Err(ProtocolError::Malformed(_))
        ));
        assert!(matches!(
            decode::<Request>(b""),
            Err(ProtocolError::Malformed(_))
        ));
    }
}
