//! Linux-PAM, spoken directly.
//!
//! Hand-written declarations for the ten library functions and three
//! structures the helper needs, the conversation function, and thin
//! wrappers that turn every return code other than `PAM_SUCCESS` into a
//! [`PamError`]. No policy lives here: which stack runs, in what order, and
//! what a refusal means is the caller's business.
//!
//! Why not a crate: `pam-sys`/`pam` also carry the machinery for WRITING
//! modules, which the helper never needs, and this slice adds no
//! dependencies. The library is linked with `#[link(name = "pam")]` below.
//! This module exists only in the `system` build (`crate::helper` is gated
//! on it), so that attribute never reaches the default build -- the
//! portable musl `qshd`, which must run without `libpam`.
//!
//! Memory ownership across the boundary, which is where a mistake here is a
//! memory-safety bug in a root process:
//!
//! - The response array the conversation function hands back is freed by
//!   the library with `free()`, so it is allocated with libc's `calloc`,
//!   never with Rust's allocator. A refused conversation allocates nothing
//!   and leaves `*resp` NULL. See [`converse`].
//! - `pam_start` keeps the conversation's `appdata_ptr` for the handle's
//!   whole life. It points at a [`ConvState`] on the heap that [`Pam`] owns
//!   and frees only after `pam_end` (see [`ConvBox`]).
//! - `pam_getenvlist` hands back an array and strings that are ours to
//!   `free()`; [`Pam::env_list`] copies them and frees each one.
//! - A handle that `pam_start` did not report as started is never read and
//!   never ended (see `Pam::begin`).
//!
//! Only the tests may name `pam_start_confdir`: it is versioned
//! `LIBPAM_1.4`, and one reference to it anywhere in the daemon -- even an
//! unused branch the optimizer happens to keep -- makes the dynamic loader
//! refuse the whole binary on Linux-PAM 1.3.1 (Ubuntu 20.04, RHEL 8). Its
//! declaration, `Pam::start_confdir` and the branch that calls it are all
//! `#[cfg(test)]`. `scripts/check-pam-linkage.sh` checks the result.
//!
//! Linux only: the conversation function reads its messages the Linux-PAM
//! way, as an array of pointers (`msg[i]->msg_style`), which is not how
//! Solaris lays them out.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::marker::{PhantomData, PhantomPinned};
#[cfg(test)]
use std::os::unix::ffi::OsStrExt as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::path::Path;
use std::ptr::{self, NonNull};

use nix::libc;

// Values from Linux-PAM's `<security/_pam_types.h>` (1.5.3). They are part
// of the library's ABI and have not changed since the header first had them.

/// Every call's code for "it worked".
pub(super) const PAM_SUCCESS: c_int = 0;
/// A code for a failure that is not the stack's verdict: here, an argument
/// that cannot be handed to C at all.
pub(super) const PAM_SYSTEM_ERR: c_int = 4;
/// The conversation could not allocate its answer.
pub(super) const PAM_BUF_ERR: c_int = 5;
/// The conversation refused.
pub(super) const PAM_CONV_ERR: c_int = 19;

/// Item: the terminal the session runs on.
const PAM_TTY: c_int = 3;
/// Item: where the client connected from.
const PAM_RHOST: c_int = 4;

/// `pam_setcred` flag: set the account's credentials up.
const PAM_ESTABLISH_CRED: c_int = 0x0002;
/// `pam_setcred` flag: take them down again.
const PAM_DELETE_CRED: c_int = 0x0004;

/// Message style: a prompt whose answer is not shown (a password).
///
/// Named but never matched on outside the tests: [`converse`] refuses every
/// style that is not a message, so the two prompt styles are refused by
/// falling through rather than by being compared against. They are declared
/// all the same, because a reader of the conversation function has to know
/// what it is refusing, and the tests build real prompts out of them.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const PAM_PROMPT_ECHO_OFF: c_int = 1;
/// Message style: a prompt whose answer is shown (a name). Declared and not
/// matched on, exactly as [`PAM_PROMPT_ECHO_OFF`] is.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const PAM_PROMPT_ECHO_ON: c_int = 2;
/// Message style: an error to show the user; no answer wanted.
pub(super) const PAM_ERROR_MSG: c_int = 3;
/// Message style: information to show the user; no answer wanted.
pub(super) const PAM_TEXT_INFO: c_int = 4;

/// The most messages one conversation call may carry.
const PAM_MAX_NUM_MSG: c_int = 32;

/// `pam_handle_t`: opaque, only ever behind a pointer the library made.
#[repr(C)]
pub(super) struct PamHandle {
    _opaque: [u8; 0],
    _not_send_sync_or_unpin: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `struct pam_message`.
#[repr(C)]
pub(super) struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

/// `struct pam_response`. The library frees an array of these, and every
/// non-NULL `resp` in it, with `free()`.
#[repr(C)]
pub(super) struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

/// The conversation function's C signature. Linux-PAM's `msg` is
/// `const struct pam_message **`: an array of `num_msg` pointers.
type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

/// `struct pam_conv`.
#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    // Linux-PAM 1.4+, versioned `@LIBPAM_1.4`. A reference to it anywhere
    // in the daemon makes the dynamic loader refuse the whole binary on
    // Linux-PAM 1.3.1 (Ubuntu 20.04, RHEL 8), before `main`. Test-only.
    #[cfg(test)]
    fn pam_start_confdir(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(pamh: *mut PamHandle, pam_status: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_open_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_close_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_setcred(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_getenvlist(pamh: *mut PamHandle) -> *mut *mut c_char;
    fn pam_strerror(pamh: *mut PamHandle, errnum: c_int) -> *const c_char;
}

/// A PAM call that did not return `PAM_SUCCESS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PamError {
    /// The code the library returned.
    pub(super) code: c_int,
    /// Which call it was, or what stopped the call being made.
    pub(super) what: &'static str,
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (PAM code {})",
            self.what,
            describe(self.code),
            self.code
        )
    }
}

impl std::error::Error for PamError {}

/// The library's own words for `code`.
///
/// `pam_strerror` is handed a NULL handle: Linux-PAM ignores that argument
/// (it is declared without `nonnull`, unlike every other call here), and a
/// [`PamError`] outlives the handle it came from. The text comes back in the
/// C locale -- nothing in `qshd` calls `setlocale` -- so the log is English.
fn describe(code: c_int) -> String {
    // SAFETY: `pam_strerror` takes a nullable handle it does not use and
    // returns a pointer to a static string, which is copied at once.
    let text = unsafe { pam_strerror(ptr::null_mut(), code) };
    if text.is_null() {
        return "unknown PAM error".to_string();
    }
    // SAFETY: non-NULL, and NUL-terminated as every `pam_strerror` answer is.
    unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned()
}

/// Which way [`Pam::setcred`] goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cred {
    /// `PAM_ESTABLISH_CRED`, before the session opens.
    Establish,
    /// `PAM_DELETE_CRED`, after it closes.
    Delete,
}

impl Cred {
    fn flags(self) -> c_int {
        match self {
            Cred::Establish => PAM_ESTABLISH_CRED,
            Cred::Delete => PAM_DELETE_CRED,
        }
    }
}

/// What the conversation function's `appdata_ptr` points at: everything the
/// modules said during one handle's life, in order.
#[derive(Debug, Default)]
pub(super) struct ConvState {
    pub(super) messages: Vec<String>,
    /// The `PAM_ERROR_MSG` ones alone, in order -- a subset of `messages`,
    /// kept apart rather than filtered later because the style is known
    /// only here, inside the conversation.
    ///
    /// They are worth telling apart: an error message on a transaction that
    /// SUCCEEDS is "something is wrong but we let you in" -- an optional
    /// module that failed, a warning about an expiring password -- and it
    /// reaches nobody otherwise. There is no interactive side to a channel
    /// while its session is being opened, so it cannot be shown to the
    /// person logging in; the helper's log is where it has to go. See
    /// `super::monitor::Session::notes`.
    pub(super) errors: Vec<String>,
    /// How many characters of [`ConvState::messages`] have been kept so
    /// far -- what [`ConvState::keep`] stops at. A running total rather
    /// than a count of entries, because what reads `messages`
    /// (`super::monitor::Session::refusal_detail`) joins them and cuts the
    /// join by LENGTH.
    kept_chars: usize,
}

/// The most of any one thing a module says that a transaction keeps.
///
/// Everything else that crosses into this root process is bounded by
/// construction -- `MAX_MESSAGE_LEN`, `MAX_VERDICT_LEN`, `NGROUPS_MAX`,
/// `server::MAX_RHOST_LEN`, `MAX_AUTHORIZED_KEYS_BYTES`,
/// `super::monitor::MAX_NOTES` -- and this was the one thing that was not.
/// The source is the administrator's own modules rather than the network,
/// so it is hygiene rather than an attack surface; but the argument
/// `MAX_NOTES` makes for itself ("a module that complained a hundred times
/// per login would be an amplifier") is about what a stack can make this
/// process do, and it applies to holding the words exactly as it applies to
/// forwarding them. `MAX_NOTES` bounded only the forwarding.
///
/// 512 characters, and chosen to be TRANSPARENT rather than merely small:
/// it is what `super::monitor::sanitized_detail` cuts every one of these
/// strings to on its way to the log, so no reader can tell the difference
/// between a message kept whole and one kept this far. Characters and not
/// bytes, for the same reason: that cut counts characters, so a cut counted
/// in bytes here could leave a multi-byte message shorter than the reader
/// was going to take. The relationship is pinned by
/// `tests::what_a_transaction_keeps_covers_what_its_readers_take`, since
/// the numbers live in two modules.
const MAX_KEPT_CHARS: usize = 512;

/// The most `PAM_ERROR_MSG` messages one transaction keeps.
///
/// Eight, which is what `super::monitor::Session::notes` takes off
/// [`ConvState::errors`] -- so, again, no reader can tell. Pinned against
/// that number by
/// `tests::what_a_transaction_keeps_covers_what_its_readers_take`.
const MAX_KEPT_ERRORS: usize = 8;

impl ConvState {
    /// Keep what one module said, within this process's own bounds.
    ///
    /// The one place anything enters either list, so the bounds are applied
    /// where the value arrives rather than wherever it is eventually read
    /// -- the same rule `server::sanitized_rhost` follows for the other
    /// thing the privileged side keeps on somebody else's say-so.
    ///
    /// The two lists are bounded separately because they are read
    /// separately and differently: `errors` by entry (the first
    /// `MAX_NOTES` of them), `messages` by the length of their join. A
    /// single cap on both would have to be the larger of the two and would
    /// bound neither tightly.
    fn keep(&mut self, style: c_int, text: String) {
        let text: String = text.chars().take(MAX_KEPT_CHARS).collect();
        if style == PAM_ERROR_MSG && self.errors.len() < MAX_KEPT_ERRORS {
            self.errors.push(text.clone());
        }
        // Once this much has been kept, the join of these strings is
        // already longer than anything that reads it will take, so a
        // further message cannot change what any reader sees. The one
        // message that crosses the line is kept whole rather than split,
        // which is why the bound is "at most `MAX_KEPT_CHARS` more than
        // `MAX_KEPT_CHARS`" and not a hard ceiling -- two of a number that
        // small is still a number.
        if self.kept_chars < MAX_KEPT_CHARS {
            self.kept_chars = self.kept_chars.saturating_add(text.chars().count());
            self.messages.push(text);
        }
    }
}

/// A [`ConvState`] at a fixed heap address, owned through a raw pointer.
///
/// Not a `Box` field: the library keeps a raw pointer to the state, and a
/// `Box` asserts unique access each time it is moved -- as [`Pam`] is when a
/// constructor returns it -- which a pointer kept on the side would violate.
/// The allocation itself never moves; only this pointer to it does.
struct ConvBox(NonNull<ConvState>);

impl ConvBox {
    fn new() -> ConvBox {
        ConvBox(NonNull::from(Box::leak(Box::default())))
    }

    fn as_ptr(&self) -> *mut ConvState {
        self.0.as_ptr()
    }
}

impl Drop for ConvBox {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `Box::leak` in `new`, and this is
        // its only owner; whoever handed it to a PAM handle ended that handle
        // first (`Pam`'s `Drop` runs before its fields are dropped).
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

/// Where a transaction's stack is read from.
enum Stack {
    /// `/etc/pam.d/<service>`, through `pam_start`: the daemon's only choice.
    System,
    /// `<dir>/<service>`, through `pam_start_confdir`: tests only.
    #[cfg(test)]
    Dir(CString),
}

/// One PAM transaction: a handle from `pam_start`, ended exactly once when
/// this is dropped.
pub(super) struct Pam {
    /// Non-NULL from construction until [`Pam::end`]; NULL after it.
    handle: *mut PamHandle,
    /// The service the stack was read for. Linux-PAM copies it, but nothing
    /// here depends on that.
    service: CString,
    /// The code of the most recent call, which `pam_end` passes on to the
    /// modules' cleanup functions.
    last_code: c_int,
    /// The conversation's state. Declared last and freed only after
    /// `pam_end` (see `Drop`), since the handle points at it until then.
    conv: ConvBox,
}

impl fmt::Debug for Pam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pam")
            .field("service", &self.service)
            .field("live", &!self.handle.is_null())
            .field("last_code", &self.last_code)
            .finish_non_exhaustive()
    }
}

impl Pam {
    /// Start a transaction for `user` with the stack in
    /// `/etc/pam.d/<service>`, and record the terminal and the client's
    /// address for the modules.
    pub(super) fn start(
        service: &str,
        user: &str,
        tty: &str,
        rhost: &str,
    ) -> Result<Pam, PamError> {
        Pam::begin(Stack::System, service, user, tty, rhost)
    }

    /// As [`Pam::start`], with the stack read from `<dir>/<service>` instead
    /// (`pam_start_confdir`, Linux-PAM 1.4+): what lets the PAM tests run
    /// without privileges. Test-only, like the declaration it calls (see
    /// `pam_start_confdir`).
    #[cfg(test)]
    pub(super) fn start_confdir(
        dir: &Path,
        service: &str,
        user: &str,
        tty: &str,
        rhost: &str,
    ) -> Result<Pam, PamError> {
        let dir = c_string(
            dir.as_os_str().as_bytes(),
            "the PAM configuration directory holds a NUL byte",
        )?;
        Pam::begin(Stack::Dir(dir), service, user, tty, rhost)
    }

    fn begin(
        stack: Stack,
        service: &str,
        user: &str,
        tty: &str,
        rhost: &str,
    ) -> Result<Pam, PamError> {
        // Everything that can fail without PAM fails first, while there is
        // nothing to end.
        let service = c_string(service.as_bytes(), "the PAM service name holds a NUL byte")?;
        let user = c_string(user.as_bytes(), "the account name holds a NUL byte")?;
        let tty = c_string(tty.as_bytes(), "the terminal name holds a NUL byte")?;
        let rhost = c_string(rhost.as_bytes(), "the client address holds a NUL byte")?;

        let conv = ConvBox::new();
        let pam_conv = PamConv {
            conv: converse,
            appdata_ptr: conv.as_ptr().cast(),
        };
        let mut handle: *mut PamHandle = ptr::null_mut();
        // SAFETY: every string is a live NUL-terminated `CString`, which the
        // library copies; `pam_conv` is copied too, and the state its
        // `appdata_ptr` names lives in `conv`, which the `Pam` built below
        // keeps until after `pam_end`.
        let code = unsafe {
            match &stack {
                Stack::System => pam_start(service.as_ptr(), user.as_ptr(), &pam_conv, &mut handle),
                #[cfg(test)]
                Stack::Dir(dir) => pam_start_confdir(
                    service.as_ptr(),
                    user.as_ptr(),
                    &pam_conv,
                    dir.as_ptr(),
                    &mut handle,
                ),
            }
        };
        if code != PAM_SUCCESS {
            // `handle` is not read, and `pam_end` is not called: whatever
            // the library did with it is not a live handle. (Linux-PAM
            // 1.5.3 leaves it NULL after freeing, or untouched when an
            // argument is refused -- but nothing here depends on that.) No
            // module has run, so nothing kept `conv`'s address; it is freed
            // on the way out.
            return Err(PamError {
                code,
                what: "pam_start",
            });
        }
        let mut pam = Pam {
            handle,
            service,
            last_code: code,
            conv,
        };
        // A failure from here on drops `pam`, which ends the handle.
        pam.set_item(PAM_TTY, &tty, "pam_set_item(PAM_TTY)")?;
        pam.set_item(PAM_RHOST, &rhost, "pam_set_item(PAM_RHOST)")?;
        Ok(pam)
    }

    /// The account stack's verdict: expired, locked, not allowed here.
    pub(super) fn acct_mgmt(&mut self) -> Result<(), PamError> {
        // SAFETY: `handle` is live (see the field).
        let code = unsafe { pam_acct_mgmt(self.handle, 0) };
        self.record(code, "pam_acct_mgmt")
    }

    /// Open the session: the session stack's "open" half.
    pub(super) fn open_session(&mut self) -> Result<(), PamError> {
        // SAFETY: `handle` is live (see the field).
        let code = unsafe { pam_open_session(self.handle, 0) };
        self.record(code, "pam_open_session")
    }

    /// Close the session: the session stack's "close" half.
    pub(super) fn close_session(&mut self) -> Result<(), PamError> {
        // SAFETY: `handle` is live (see the field).
        let code = unsafe { pam_close_session(self.handle, 0) };
        self.record(code, "pam_close_session")
    }

    /// Set the account's credentials up, or take them down.
    pub(super) fn setcred(&mut self, what: Cred) -> Result<(), PamError> {
        // SAFETY: `handle` is live (see the field).
        let code = unsafe { pam_setcred(self.handle, what.flags()) };
        self.record(code, "pam_setcred")
    }

    /// The environment the modules set, as `KEY=VALUE` strings ready for a
    /// child's `execve`. Empty if the library could not produce it (it
    /// returns NULL only when it cannot allocate the copy).
    pub(super) fn env_list(&self) -> Vec<CString> {
        // SAFETY: `handle` is live (see the field). The answer is a fresh
        // NULL-terminated array of fresh strings, all ours to `free()`.
        let list = unsafe { pam_getenvlist(self.handle) };
        if list.is_null() {
            return Vec::new();
        }
        let mut env = Vec::new();
        for i in 0.. {
            // SAFETY: `list` is NULL-terminated, and this stops at the NULL.
            let entry = unsafe { *list.add(i) };
            if entry.is_null() {
                break;
            }
            // SAFETY: a NUL-terminated string the library allocated with
            // `malloc`; copied, then freed exactly once.
            env.push(unsafe { CStr::from_ptr(entry) }.to_owned());
            unsafe { libc::free(entry.cast()) };
        }
        // SAFETY: the array itself, also from `malloc`, freed once.
        unsafe { libc::free(list.cast()) };
        env
    }

    /// What the modules said during this transaction, in order.
    pub(super) fn messages(&self) -> &[String] {
        // SAFETY: `conv` is alive as long as `self`. The conversation
        // function writes to it only while one of the `&mut self` calls
        // above is running, and no `&self` borrow can exist then.
        unsafe { &(*self.conv.as_ptr()).messages }
    }

    /// The subset of [`Pam::messages`] the modules marked as ERRORS -- see
    /// [`ConvState::errors`] for why the distinction is worth keeping.
    pub(super) fn error_messages(&self) -> &[String] {
        // SAFETY: as for `messages`.
        unsafe { &(*self.conv.as_ptr()).errors }
    }

    fn set_item(&mut self, item: c_int, value: &CStr, what: &'static str) -> Result<(), PamError> {
        // SAFETY: `handle` is live; the library copies the string.
        let code = unsafe { pam_set_item(self.handle, item, value.as_ptr().cast()) };
        self.record(code, what)
    }

    /// Remember `code` for `pam_end`, and turn it into a result.
    fn record(&mut self, code: c_int, what: &'static str) -> Result<(), PamError> {
        self.last_code = code;
        if code == PAM_SUCCESS {
            Ok(())
        } else {
            Err(PamError { code, what })
        }
    }

    /// End the transaction, once: `pam_end` for a live handle, then the
    /// handle is forgotten, so a second call does nothing. Only `Drop` calls
    /// this outside the tests, and no method is called after it.
    ///
    /// Returns whether this call ended the transaction.
    ///
    /// `last_code` reaches only the modules' cleanup functions (the ones
    /// registered with `pam_set_data`); no stock module shows what it got
    /// without privileges, so which code is passed has no test here.
    fn end(&mut self) -> bool {
        if self.handle.is_null() {
            return false;
        }
        // SAFETY: `handle` is live and is never used again. The
        // conversation state it points at is still alive: `conv` is dropped
        // after this.
        unsafe { pam_end(self.handle, self.last_code) };
        self.handle = ptr::null_mut();
        true
    }
}

impl Drop for Pam {
    fn drop(&mut self) {
        // Runs before any field is dropped, so `conv` outlives the handle:
        // a module may still converse from its cleanup, inside `pam_end`.
        // No stock module does, so freeing the state first would pass every
        // test here -- the order is kept by this structure, not by a test.
        self.end();
    }
}

fn c_string(bytes: &[u8], what: &'static str) -> Result<CString, PamError> {
    CString::new(bytes).map_err(|_| PamError {
        code: PAM_SYSTEM_ERR,
        what,
    })
}

/// The conversation function handed to `pam_start`.
///
/// There is no interactive channel while a login is being set up, so any
/// call that asks for input (`PAM_PROMPT_ECHO_OFF`, `PAM_PROMPT_ECHO_ON`,
/// or a style this code does not know) is refused as a whole with
/// `PAM_CONV_ERR`: an empty answer would read as a correct empty password
/// to a module that asked for one, and a module must not get a
/// half-answered conversation either. The messages (`PAM_TEXT_INFO`,
/// `PAM_ERROR_MSG`) in the call are kept in [`ConvState::messages`] and
/// written to the helper's log either way.
///
/// No panic leaves this function: [`converse_logging_to`] contains one and
/// refuses the call instead. (Were one to escape anyway, Rust aborts the
/// process at an `extern "C"` boundary rather than unwind into the library.)
unsafe extern "C" fn converse(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract is forwarded unchanged.
    unsafe {
        converse_logging_to(
            num_msg,
            msg,
            resp,
            appdata_ptr,
            &log_module_message,
            libc::calloc,
        )
    }
}

/// Where [`converse`] writes what a module said.
fn log_module_message(style: c_int, text: &str) {
    let (kind, level) = if style == PAM_ERROR_MSG {
        ("error", crate::log::Level::Warn)
    } else {
        ("info", crate::log::Level::Info)
    };
    crate::log::record(
        level,
        "helper",
        &format!("a PAM module says ({kind}): {text:?}"),
    );
}

/// The log line for a conversation that panicked and was refused.
const CONVERSATION_PANICKED_LOG: &str = "the PAM conversation panicked; the call was refused";

/// The allocator of a conversation's answer array: `calloc`'s signature.
type AnswerAllocator = unsafe extern "C" fn(usize, usize) -> *mut c_void;

/// [`converse`], with the message log and the answer's allocator passed in,
/// so a test can make the one panic and the other fail.
///
/// # Safety
///
/// As for any conversation function: `resp` is NULL or writable; `msg` is
/// NULL or points at `num_msg` pointers, each NULL or pointing at a
/// `pam_message` whose `msg` is NULL or NUL-terminated; `appdata_ptr` is
/// NULL or points at a [`ConvState`] nothing else is using during the call.
unsafe fn converse_logging_to(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
    log: &dyn Fn(c_int, &str),
    answer_array: AnswerAllocator,
) -> c_int {
    if resp.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: `resp` is writable. NULL until there is an answer to give.
    unsafe { *resp = ptr::null_mut() };
    // SAFETY: the caller's contract is forwarded unchanged.
    let heard = catch_unwind(AssertUnwindSafe(|| unsafe {
        hear(num_msg, msg, appdata_ptr, log)
    }));
    let count = match heard {
        Ok(Some(count)) => count,
        Ok(None) => return PAM_CONV_ERR,
        Err(payload) => {
            // Dropping the payload could itself panic, and this is outside
            // the catch: leak it rather than risk unwinding into C.
            std::mem::forget(payload);
            crate::log::error("helper", CONVERSATION_PANICKED_LOG);
            return PAM_CONV_ERR;
        }
    };
    // Nothing below can panic. The array is the library's to `free()`, so
    // it comes from `calloc`, whose zeroes are a NULL `resp` and a zero
    // `resp_retcode` in every entry: nothing is answered, only acknowledged.
    // SAFETY: plain allocation; `count` is between 1 and PAM_MAX_NUM_MSG.
    let answer = unsafe { answer_array(count, std::mem::size_of::<PamResponse>()) };
    if answer.is_null() {
        return PAM_BUF_ERR;
    }
    // SAFETY: `resp` is writable.
    unsafe { *resp = answer.cast() };
    PAM_SUCCESS
}

/// Read one conversation call: keep and log its messages, and say whether
/// it can be acknowledged -- `Some(num_msg)` when it only talks, `None` when
/// it asks for anything or is malformed. Allocates nothing the library sees.
///
/// # Safety
///
/// As for [`converse_logging_to`].
unsafe fn hear(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    appdata_ptr: *mut c_void,
    log: &dyn Fn(c_int, &str),
) -> Option<usize> {
    if num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG || msg.is_null() || appdata_ptr.is_null() {
        return None;
    }
    let count = num_msg as usize;
    // SAFETY: `appdata_ptr` is the `ConvState` the handle was started with
    // (see `Pam::begin`), alive and not otherwise in use for the call.
    let state = unsafe { &mut *appdata_ptr.cast::<ConvState>() };
    let mut answerable = true;
    for i in 0..count {
        // SAFETY: `msg` points at `count` pointers.
        let message = unsafe { *msg.add(i) };
        if message.is_null() {
            answerable = false;
            continue;
        }
        // SAFETY: a non-NULL pointer to a `pam_message`.
        let (style, text) = unsafe { ((*message).msg_style, (*message).msg) };
        match style {
            PAM_TEXT_INFO | PAM_ERROR_MSG => {
                let text = if text.is_null() {
                    String::new()
                } else {
                    // SAFETY: a NUL-terminated string, copied at once.
                    unsafe { CStr::from_ptr(text) }
                        .to_string_lossy()
                        .into_owned()
                };
                // Logged as it arrived, kept within this process's bounds
                // -- see [`ConvState::keep`]. The two differ on purpose:
                // the log call is a no-op in the only process that ever
                // runs a stack (`crate::log::mute`, `super::monitor`), so
                // what is bounded here is what this process HOLDS.
                log(style, &text);
                state.keep(style, text);
            }
            // The two prompts, and any style this code does not know
            // (`PAM_RADIO_TYPE`, `PAM_BINARY_PROMPT`, ...): each wants an
            // answer there is no one to give.
            _ => answerable = false,
        }
    }
    answerable.then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::UnsafeCell;
    use std::panic::catch_unwind;

    /// `PAM_AUTH_ERR`: what `pam_deny.so` answers for the account stack
    /// (its `pam_sm_acct_mgmt` is `return PAM_AUTH_ERR`).
    const PAM_AUTH_ERR: c_int = 7;
    /// `PAM_SESSION_ERR`: what `pam_deny.so` answers for either session
    /// half.
    const PAM_SESSION_ERR: c_int = 14;
    /// `PAM_CRED_ERR`: what `pam_deny.so` answers for `pam_setcred`.
    const PAM_CRED_ERR: c_int = 17;
    /// `PAM_ABORT`: what `pam_start_confdir` answers when it cannot read
    /// the stack.
    const PAM_ABORT: c_int = 26;
    /// `PAM_RADIO_TYPE`: a Linux-PAM message style that wants an answer.
    const PAM_RADIO_TYPE: c_int = 5;

    const PERMIT_STACK: &str = "auth required pam_permit.so\n\
                                account required pam_permit.so\n\
                                session required pam_permit.so\n";

    fn current_account_name() -> String {
        nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .expect("passwd")
            .expect("this account exists")
            .name
    }

    /// A PAM configuration directory of the test's own, with `stacks`
    /// written into it as `(service, contents)`.
    fn confdir(stacks: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (service, contents) in stacks {
            std::fs::write(dir.path().join(service), contents).expect("write");
        }
        dir
    }

    fn start_in(dir: &Path, service: &str) -> Pam {
        Pam::start_confdir(
            dir,
            service,
            &current_account_name(),
            "/dev/pts/0",
            "203.0.113.7",
        )
        .expect("start")
    }

    /// A conversation state a test hands to the conversation function the
    /// way `Pam` does: by address, with the function writing through it.
    #[derive(Default)]
    struct MessageLog(UnsafeCell<ConvState>);

    impl MessageLog {
        fn as_ptr(&self) -> *mut c_void {
            self.0.get().cast()
        }

        fn messages(&self) -> Vec<String> {
            // SAFETY: no conversation call is running.
            unsafe { (*self.0.get()).messages.clone() }
        }

        fn errors(&self) -> Vec<String> {
            // SAFETY: as for `messages`.
            unsafe { (*self.0.get()).errors.clone() }
        }
    }

    fn pam_message(style: c_int, text: &'static CStr) -> PamMessage {
        PamMessage {
            msg_style: style,
            msg: text.as_ptr(),
        }
    }

    /// Call the conversation function the way a module does, with
    /// `messages` as the array of pointers, and hand back the code and the
    /// answer array (NULL, or the library's to free -- see [`free_answer`]).
    fn converse_with_log(
        messages: &[PamMessage],
        state: &MessageLog,
        log: &dyn Fn(c_int, &str),
    ) -> (c_int, *mut PamResponse) {
        let mut pointers: Vec<*const PamMessage> =
            messages.iter().map(|m| m as *const PamMessage).collect();
        let mut resp: *mut PamResponse = ptr::dangling_mut();
        let num = c_int::try_from(pointers.len()).expect("message count");
        // SAFETY: `pointers` holds `num` live messages with static texts;
        // `resp` is writable; `state` is not otherwise in use.
        let code = unsafe {
            converse_logging_to(
                num,
                pointers.as_mut_ptr(),
                &mut resp,
                state.as_ptr(),
                log,
                libc::calloc,
            )
        };
        (code, resp)
    }

    fn quiet(_: c_int, _: &str) {}

    /// What a transaction KEEPS is bounded, and not only what it forwards.
    ///
    /// Everything else that crosses into this root process is bounded by
    /// construction; the words of an administrator's modules were the one
    /// thing that was not. `super::super::monitor::MAX_NOTES` bounded how
    /// many of them reach the log and `sanitized_detail` how much of each,
    /// while the lists they are taken from grew with every call.
    #[test]
    fn what_a_transaction_keeps_is_bounded() {
        let state = MessageLog::default();
        let long = CString::new("x".repeat(MAX_KEPT_CHARS + 500)).expect("a run of x has no NUL");
        let chatter = CString::new("chatter").expect("no NUL");

        // A stack that says far more, and far longer, than any reader of
        // either list will take: fifty calls, each carrying one complaint
        // past the length cap and one piece of chatter.
        for _ in 0..50 {
            let messages = [
                PamMessage {
                    msg_style: PAM_ERROR_MSG,
                    msg: long.as_ptr(),
                },
                PamMessage {
                    msg_style: PAM_TEXT_INFO,
                    msg: chatter.as_ptr(),
                },
            ];
            let (code, resp) = converse_with_log(&messages, &state, &quiet);
            assert_eq!(
                code, PAM_SUCCESS,
                "setup: a call that only talks must still be acknowledged"
            );
            free_answer(resp, messages.len());
        }

        let kept = state.messages();
        let errors = state.errors();
        // Positive control: a transaction that keeps NOTHING would satisfy
        // every bound below, and would be a worse bug than the one this
        // fixes -- a refusal with no reason anywhere.
        assert!(
            !kept.is_empty() && !errors.is_empty(),
            "control: a module that talks must still be heard at all"
        );
        assert!(
            kept.iter()
                .all(|said| said.chars().count() <= MAX_KEPT_CHARS),
            "no one thing a module says may be kept past MAX_KEPT_CHARS, since nothing reads \
             more of it than that; kept lengths {:?}",
            kept.iter().map(|s| s.chars().count()).collect::<Vec<_>>()
        );
        assert!(
            errors.len() <= MAX_KEPT_ERRORS,
            "a module that complains in a loop must not fill a root process's memory with it; \
             kept {} errors",
            errors.len()
        );
        let together: usize = kept.iter().map(|s| s.chars().count()).sum();
        assert!(
            together <= 2 * MAX_KEPT_CHARS,
            "and the messages stop being kept once their join is already longer than anything \
             that reads it will take -- at most one message past the line, never a hundred; \
             kept {together} characters"
        );
    }

    /// And the bounds above cover what their readers actually take, which
    /// is what makes them invisible rather than merely small.
    ///
    /// The numbers live in two modules -- the readers are
    /// `super::super::monitor::Session::notes` and
    /// `Session::refusal_detail` -- so nothing but this checks that they
    /// still line up. Each is also pinned by VALUE: every assertion in
    /// `what_a_transaction_keeps_is_bounded` scales with the constants and
    /// would pass at any value of them.
    #[test]
    fn what_a_transaction_keeps_covers_what_its_readers_take() {
        assert_eq!(
            MAX_KEPT_ERRORS,
            super::super::monitor::MAX_NOTES,
            "a login may put MAX_NOTES lines in the log, so keeping fewer errors than that \
             would silently shorten what an administrator is told"
        );
        assert_eq!(
            MAX_KEPT_CHARS,
            super::super::monitor::MAX_REFUSAL_DETAIL,
            "and MAX_REFUSAL_DETAIL is what every one of these strings is cut to on its way \
             out, so keeping less would shorten a refusal's reason"
        );
        assert_eq!(MAX_KEPT_ERRORS, 8, "see MAX_KEPT_ERRORS' own docs");
        assert_eq!(MAX_KEPT_CHARS, 512, "see MAX_KEPT_CHARS' own docs");
    }

    /// Check an acknowledgement the way the library would use it, then free
    /// it the way the library does: every entry answers nothing, and the
    /// array goes back with `free()`.
    fn free_answer(resp: *mut PamResponse, count: usize) {
        assert!(
            !resp.is_null(),
            "an acknowledged call must hand back an array"
        );
        for i in 0..count {
            // SAFETY: `count` entries, from the conversation function.
            let entry = unsafe { &*resp.add(i) };
            assert!(entry.resp.is_null(), "entry {i} must answer nothing");
            assert_eq!(entry.resp_retcode, 0, "entry {i}'s retcode must be zero");
        }
        // SAFETY: the array came from `calloc`, and nothing else frees it.
        unsafe { libc::free(resp.cast()) };
    }

    /// The account stack decides, and a refusal comes back as a refusal:
    /// `pam_deny` in the account stack must fail `acct_mgmt`, `pam_permit`
    /// must pass it. No privileges needed: the service file lives in a temp
    /// dir that `pam_start_confdir` is told about. Run in a process of its
    /// own, like its siblings that start a transaction here: doing that in
    /// the test binary itself leaves any later test in this binary that
    /// opens a channel refused with ENOTTY.
    #[test]
    fn the_account_stack_decides() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_account_stack_decides_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_account_stack_decides`].
    #[test]
    #[ignore = "runs only via the_account_stack_decides, in a process of its own"]
    fn the_account_stack_decides_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("qshd-test-permit"), PERMIT_STACK).expect("write");
        std::fs::write(
            dir.path().join("qshd-test-deny"),
            "auth required pam_permit.so\n\
             account required pam_deny.so\n\
             session required pam_permit.so\n",
        )
        .expect("write");
        let me = current_account_name();

        let mut ok = Pam::start_confdir(
            dir.path(),
            "qshd-test-permit",
            &me,
            "/dev/pts/0",
            "203.0.113.7",
        )
        .expect("start");
        ok.acct_mgmt().expect("pam_permit must admit");

        let mut denied = Pam::start_confdir(
            dir.path(),
            "qshd-test-deny",
            &me,
            "/dev/pts/0",
            "203.0.113.7",
        )
        .expect("start");
        let err = denied.acct_mgmt().expect_err("pam_deny must refuse");
        // The exact code is what ties the refusal to `pam_deny`'s account
        // stack: its `pam_sm_acct_mgmt` returns `PAM_AUTH_ERR`. A harness
        // that could not reach the stack at all -- a wrong directory, a
        // missing or unreadable service file -- fails already at
        // `pam_start_confdir`, with `PAM_ABORT`, which `.expect("start")`
        // above catches; and a wrapper that invented its own failure would
        // not produce this code.
        assert_eq!(
            err.code, PAM_AUTH_ERR,
            "the refusal must come from pam_deny's account stack, not from a \
             wrapper that failed to start at all -- got {err}"
        );
        assert_eq!(
            (ok.last_code, denied.last_code),
            (PAM_SUCCESS, PAM_AUTH_ERR),
            "pam_end must be handed each transaction's last verdict"
        );
    }

    /// A stack that cannot be read fails at the start, with the library's
    /// code and words, and no handle comes out of it. Run in a process of
    /// its own, like its siblings that start a transaction here: doing that
    /// in the test binary itself leaves any later test in this binary that
    /// opens a channel refused with ENOTTY.
    #[test]
    fn a_stack_that_cannot_be_read_fails_to_start() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::a_stack_that_cannot_be_read_fails_to_start_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`a_stack_that_cannot_be_read_fails_to_start`].
    #[test]
    #[ignore = "runs only via a_stack_that_cannot_be_read_fails_to_start, in a process of its own"]
    fn a_stack_that_cannot_be_read_fails_to_start_body() {
        let dir = confdir(&[("qshd-test-permit", PERMIT_STACK)]);
        // Positive control, same directory and account: the start works.
        start_in(dir.path(), "qshd-test-permit");

        let err = Pam::start_confdir(
            dir.path(),
            "qshd-test-absent",
            &current_account_name(),
            "/dev/pts/0",
            "203.0.113.7",
        )
        .expect_err("a service with no stack file must not start");
        assert_eq!(
            (err.code, err.what),
            (PAM_ABORT, "pam_start"),
            "a missing stack must fail the start itself -- got {err}"
        );
        assert_eq!(
            err.to_string(),
            "pam_start: Critical error - immediate abort (PAM code 26)",
            "the error must carry the library's own words"
        );
    }

    /// Where Linux-PAM distributions keep the system's stacks: the
    /// administrator's directory, and the vendor directories that
    /// openSUSE and others use instead.
    const SYSTEM_STACK_DIRS: [&str; 3] = ["/etc/pam.d", "/usr/lib/pam.d", "/usr/etc/pam.d"];

    /// The plain start reads the system's stacks, not a directory of its
    /// own: a service with no file anywhere starts there, on Linux-PAM's
    /// `other` fallback, while the same name fails to start from a directory
    /// that has neither. Nothing is called on the handle: what `other`
    /// decides depends on the machine. Run in a process of its own: the
    /// start loads the machine's own modules, and none of them may take the
    /// rest of the suite down.
    #[test]
    fn the_plain_start_reads_the_system_directory() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_plain_start_reads_the_system_directory_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_plain_start_reads_the_system_directory`].
    #[test]
    #[ignore = "runs only via the_plain_start_reads_the_system_directory, in a process of its own"]
    fn the_plain_start_reads_the_system_directory_body() {
        let dirs = SYSTEM_STACK_DIRS.map(Path::new);
        assert!(
            dirs.iter().any(|dir| dir.join("other").is_file()),
            "setup: this test needs Linux-PAM's fallback stack, `other`, in one of {dirs:?}"
        );
        let service = format!("qshd-test-absent-{}", std::process::id());
        for dir in dirs {
            assert!(
                !dir.join(&service).exists(),
                "setup: {service} must have no stack of its own, but {} has one",
                dir.display()
            );
        }
        let empty = confdir(&[]);
        let me = current_account_name();
        // Control, same name: with no `other` beside it, the name has no
        // stack at all.
        let err = Pam::start_confdir(empty.path(), &service, &me, "/dev/pts/0", "x")
            .expect_err("control: no stack in an empty directory");
        assert_eq!(err.code, PAM_ABORT, "control: {err}");

        let pam = Pam::start(&service, &me, "/dev/pts/0", "203.0.113.7");
        assert!(
            pam.is_ok(),
            "the plain start must fall back to the system's `other`, got {pam:?}"
        );
    }

    /// The modules see whom the transaction is for, under which service,
    /// on which terminal and from where: `pam_exec` hands them to a script
    /// in `PAM_USER`, `PAM_SERVICE`, `PAM_TTY` and `PAM_RHOST`, and the
    /// script writes them down. Run in a process of its own, like its
    /// siblings that start a transaction here: doing that in the test
    /// binary itself leaves any later test in this binary that opens a
    /// channel refused with ENOTTY.
    #[test]
    fn the_modules_see_the_account_service_terminal_and_address() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_modules_see_the_account_service_terminal_and_address_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_modules_see_the_account_service_terminal_and_address`].
    #[test]
    #[ignore = "runs only via the_modules_see_the_account_service_terminal_and_address, in a \
                process of its own"]
    fn the_modules_see_the_account_service_terminal_and_address_body() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let seen = dir.path().join("seen");
        let script = dir.path().join("record.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 echo \"$PAM_USER|$PAM_SERVICE|$PAM_TTY|$PAM_RHOST|$PAM_TYPE\" > {}\n",
                seen.display()
            ),
        )
        .expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(
            dir.path().join("qshd-test-exec"),
            format!(
                "auth required pam_permit.so\n\
                 account required pam_exec.so {}\n\
                 session required pam_permit.so\n",
                script.display()
            ),
        )
        .expect("write");
        let me = current_account_name();

        let mut pam = Pam::start_confdir(
            dir.path(),
            "qshd-test-exec",
            &me,
            "/dev/pts/7",
            "198.51.100.9",
        )
        .expect("start");
        pam.acct_mgmt().expect("the recording script must succeed");
        let seen = std::fs::read_to_string(&seen).expect("the script must have run");
        assert_eq!(
            seen.trim_end(),
            format!("{me}|qshd-test-exec|/dev/pts/7|198.51.100.9|account"),
            "the modules must see the account, the service, the terminal and the address"
        );
    }

    /// A NUL byte in any argument stops the start before PAM is involved,
    /// and says which argument it was. Run in a process of its own: its
    /// positive control starts a real transaction, and doing that in the
    /// test binary itself leaves any later test in this binary that opens
    /// a channel refused with ENOTTY.
    #[test]
    fn an_argument_with_a_nul_byte_is_refused() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::an_argument_with_a_nul_byte_is_refused_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`an_argument_with_a_nul_byte_is_refused`].
    #[test]
    #[ignore = "runs only via an_argument_with_a_nul_byte_is_refused, in a process of its own"]
    fn an_argument_with_a_nul_byte_is_refused_body() {
        let dir = confdir(&[("qshd-test-permit", PERMIT_STACK)]);
        let me = current_account_name();
        let start = |service: &str, user: &str, tty: &str, rhost: &str| {
            Pam::start_confdir(dir.path(), service, user, tty, rhost).map(|_| ())
        };
        // Positive control: the same arguments without the NUL start.
        start("qshd-test-permit", &me, "/dev/pts/0", "203.0.113.7").expect("control");

        let refusals = [
            (
                start("qshd-test-permit\0", &me, "/dev/pts/0", "203.0.113.7"),
                "the PAM service name holds a NUL byte",
            ),
            (
                start(
                    "qshd-test-permit",
                    &format!("{me}\0"),
                    "/dev/pts/0",
                    "203.0.113.7",
                ),
                "the account name holds a NUL byte",
            ),
            (
                start("qshd-test-permit", &me, "/dev/pts/0\0", "203.0.113.7"),
                "the terminal name holds a NUL byte",
            ),
            (
                start("qshd-test-permit", &me, "/dev/pts/0", "203.0.113.7\0"),
                "the client address holds a NUL byte",
            ),
        ];
        for (result, what) in refusals {
            assert_eq!(
                result,
                Err(PamError {
                    code: PAM_SYSTEM_ERR,
                    what
                }),
                "a NUL byte must be refused, naming the argument"
            );
        }
        let bad_dir = Path::new("/tmp/qshd\0test");
        assert_eq!(
            Pam::start_confdir(bad_dir, "qshd-test-permit", &me, "/dev/pts/0", "x").map(|_| ()),
            Err(PamError {
                code: PAM_SYSTEM_ERR,
                what: "the PAM configuration directory holds a NUL byte"
            }),
            "a NUL byte in the directory must be refused, naming it"
        );
    }

    /// Credentials and both session halves report what their stack
    /// decided: `pam_permit` passes all four calls, `pam_deny` fails each
    /// with its own code. Run in a process of its own, like its siblings
    /// that start a transaction here: doing that in the test binary itself
    /// leaves any later test in this binary that opens a channel refused
    /// with ENOTTY.
    #[test]
    fn the_session_and_credential_calls_report_their_stack() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_session_and_credential_calls_report_their_stack_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_session_and_credential_calls_report_their_stack`].
    #[test]
    #[ignore = "runs only via the_session_and_credential_calls_report_their_stack, in a process of \
                its own"]
    fn the_session_and_credential_calls_report_their_stack_body() {
        let dir = confdir(&[
            ("qshd-test-permit", PERMIT_STACK),
            (
                "qshd-test-deny",
                "auth required pam_deny.so\n\
                 account required pam_permit.so\n\
                 session required pam_deny.so\n",
            ),
        ]);

        // Positive control, same harness.
        let mut ok = start_in(dir.path(), "qshd-test-permit");
        ok.setcred(Cred::Establish).expect("pam_permit: establish");
        ok.open_session().expect("pam_permit: open");
        ok.close_session().expect("pam_permit: close");
        ok.setcred(Cred::Delete).expect("pam_permit: delete");

        let mut denied = start_in(dir.path(), "qshd-test-deny");
        let codes = [
            denied.setcred(Cred::Establish),
            denied.open_session(),
            denied.close_session(),
            denied.setcred(Cred::Delete),
        ];
        assert_eq!(
            codes,
            [
                Err(PamError {
                    code: PAM_CRED_ERR,
                    what: "pam_setcred"
                }),
                Err(PamError {
                    code: PAM_SESSION_ERR,
                    what: "pam_open_session"
                }),
                Err(PamError {
                    code: PAM_SESSION_ERR,
                    what: "pam_close_session"
                }),
                Err(PamError {
                    code: PAM_CRED_ERR,
                    what: "pam_setcred"
                }),
            ],
            "each call must report pam_deny's own refusal"
        );
    }

    /// `pam_setcred` gets the flag its direction names -- values from
    /// `<security/_pam_types.h>`. No stock module behaves differently for
    /// the two, so this is where the mapping is pinned.
    #[test]
    fn each_credential_direction_has_its_own_flag() {
        assert_eq!(Cred::Establish.flags(), 0x0002, "PAM_ESTABLISH_CRED");
        assert_eq!(Cred::Delete.flags(), 0x0004, "PAM_DELETE_CRED");
    }

    /// The structures match the C layout on this platform (checked against
    /// `sizeof`/`offsetof` from the installed headers).
    #[test]
    fn the_structures_have_the_c_layout() {
        use std::mem::{offset_of, size_of};
        let word = size_of::<usize>();
        assert_eq!(size_of::<PamMessage>(), 2 * word);
        assert_eq!(offset_of!(PamMessage, msg), word);
        assert_eq!(size_of::<PamResponse>(), 2 * word);
        assert_eq!(offset_of!(PamResponse, resp_retcode), word);
        assert_eq!(size_of::<PamConv>(), 2 * word);
        assert_eq!(offset_of!(PamConv, appdata_ptr), word);
    }

    /// What the session stack sets reaches the list handed to a child, and
    /// nothing else is invented: `pam_env` sets one variable, and the list
    /// holds exactly it. Run in a process of its own, like its siblings
    /// that start a transaction here: doing that in the test binary itself
    /// leaves any later test in this binary that opens a channel refused
    /// with ENOTTY.
    #[test]
    fn the_environment_the_modules_set_is_listed() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_environment_the_modules_set_is_listed_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_environment_the_modules_set_is_listed`].
    #[test]
    #[ignore = "runs only via the_environment_the_modules_set_is_listed, in a process of its own"]
    fn the_environment_the_modules_set_is_listed_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("env"),
            "QSHD_PAM_TEST DEFAULT=from-the-stack\n",
        )
        .expect("write");
        std::fs::write(dir.path().join("qshd-test-permit"), PERMIT_STACK).expect("write");
        std::fs::write(
            dir.path().join("qshd-test-env"),
            format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_env.so conffile={} envfile=/dev/null readenv=0\n\
                 session required pam_permit.so\n",
                dir.path().join("env").display()
            ),
        )
        .expect("write");

        // Positive control for the reading side: a stack that sets nothing
        // lists nothing.
        let mut plain = start_in(dir.path(), "qshd-test-permit");
        plain.open_session().expect("open");
        assert_eq!(plain.env_list(), Vec::<CString>::new(), "control");

        let mut pam = start_in(dir.path(), "qshd-test-env");
        pam.open_session().expect("pam_env must open the session");
        assert_eq!(
            pam.env_list(),
            vec![CString::new("QSHD_PAM_TEST=from-the-stack").expect("cstring")],
            "the variable pam_env set must be listed, as KEY=VALUE"
        );
        // A second list is a fresh copy: the first one's strings were ours.
        assert_eq!(pam.env_list().len(), 1, "a second list must be whole too");
    }

    /// A module that asks for input gets a refusal, not an empty answer, and a
    /// module that only talks gets its line into the log: there is no
    /// interactive channel at this point, and a silent "" would read as a
    /// correct empty password to a module that asked for one. Run in a
    /// process of its own: half two starts a real transaction, and doing
    /// that in the test binary itself leaves any later test in this binary
    /// that opens a channel refused with ENOTTY.
    #[test]
    fn the_conversation_refuses_input_and_keeps_messages() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_conversation_refuses_input_and_keeps_messages_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_conversation_refuses_input_and_keeps_messages`].
    #[test]
    #[ignore = "runs only via the_conversation_refuses_input_and_keeps_messages, in a process of \
                its own"]
    fn the_conversation_refuses_input_and_keeps_messages_body() {
        // Half one: the callback itself, called the way a module calls it. An
        // empty answer would read as a correct empty password to a module that
        // asked for one, so the answer must be a refusal.
        let collected = MessageLog::default();
        let prompt = pam_message(PAM_PROMPT_ECHO_OFF, c"Password: ");
        let mut resp: *mut PamResponse = std::ptr::null_mut();
        let code = unsafe {
            converse(
                1,
                &mut (&prompt as *const PamMessage),
                &mut resp,
                collected.as_ptr(),
            )
        };
        assert_eq!(code, PAM_CONV_ERR, "a prompt must be refused, not answered");
        assert!(
            resp.is_null(),
            "a refused conversation must allocate no response"
        );

        // Half two: a module that only talks. `pam_echo.so` emits PAM_TEXT_INFO,
        // and the line must reach the log rather than vanish.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("motd"), "a word from the modules\n").expect("write");
        std::fs::write(
            dir.path().join("qshd-test-echo"),
            format!(
                "auth required pam_permit.so\n\
                 account required pam_echo.so file={}\n\
                 account required pam_permit.so\n\
                 session required pam_permit.so\n",
                dir.path().join("motd").display()
            ),
        )
        .expect("write");
        let mut pam = Pam::start_confdir(
            dir.path(),
            "qshd-test-echo",
            &current_account_name(),
            "/dev/pts/0",
            "203.0.113.7",
        )
        .expect("start");
        pam.acct_mgmt().expect("pam_echo admits");
        assert!(
            pam.messages()
                .iter()
                .any(|m| m.contains("a word from the modules")),
            "a module's message must be kept, got {:?}",
            pam.messages()
        );
    }

    /// The errors a module reported are kept apart from what it merely
    /// said, because only the conversation knows the style.
    ///
    /// The distinction carries a decision: an error on a transaction that
    /// SUCCEEDS is forwarded to the helper's log
    /// (`super::monitor::Session::notes`), and "motd"-like chatter is not,
    /// because a root process's log must not grow at the rate an
    /// administrator's modules choose.
    #[test]
    fn an_error_a_module_reported_is_kept_apart_from_what_it_merely_said() {
        let state = MessageLog::default();
        let info = pam_message(PAM_TEXT_INFO, c"chatter");
        let error = pam_message(PAM_ERROR_MSG, c"a complaint");
        let (code, resp) = converse_with_log(&[info, error], &state, &quiet);
        assert_eq!(code, PAM_SUCCESS, "setup: a call that only talks must pass");
        free_answer(resp, 2);

        // SAFETY: no conversation call is running.
        let (messages, errors) = unsafe {
            (
                (*state.0.get()).messages.clone(),
                (*state.0.get()).errors.clone(),
            )
        };
        assert_eq!(
            messages,
            ["chatter", "a complaint"],
            "both kinds are kept, in order, as they always were"
        );
        assert_eq!(
            errors,
            ["a complaint"],
            "and the errors alone are kept a second time: the style is known only here, and \
             what reaches the helper's log on a SUCCESSFUL login is decided by it"
        );
    }

    /// The state the handle points at survives the handle being moved, and
    /// every call of one handle adds to the same list: the first call's
    /// message is still there after the second. Run in a process of its own:
    /// a handle whose state is gone makes the library write through a
    /// dangling pointer, and that must fail this test rather than take the
    /// whole suite down with it.
    #[test]
    fn the_conversation_state_lives_as_long_as_the_handle() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_conversation_state_lives_as_long_as_the_handle_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_conversation_state_lives_as_long_as_the_handle`].
    #[test]
    #[ignore = "runs only via the_conversation_state_lives_as_long_as_the_handle, in a process of \
                its own"]
    fn the_conversation_state_lives_as_long_as_the_handle_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("motd"), "said on every call\n").expect("write");
        std::fs::write(
            dir.path().join("qshd-test-echo"),
            format!(
                "auth required pam_permit.so\n\
                 account required pam_echo.so file={motd}\n\
                 account required pam_permit.so\n\
                 session required pam_echo.so file={motd}\n\
                 session required pam_permit.so\n",
                motd = dir.path().join("motd").display()
            ),
        )
        .expect("write");
        let pam = start_in(dir.path(), "qshd-test-echo");
        // Moved to the heap and back, away from where it was built, then to
        // the heap again between the two calls.
        let mut pam = *Box::new(pam);
        pam.acct_mgmt().expect("account");
        let mut pam = Box::new(pam);
        pam.open_session().expect("session");
        assert_eq!(
            pam.messages(),
            ["said on every call", "said on every call"],
            "both calls' messages must be kept, in one list"
        );
    }

    /// A call that asks for anything is refused whole, even when it also
    /// talks: nothing is allocated, and its messages are still kept. A call
    /// that only talks is acknowledged with an array the library can free.
    #[test]
    fn a_conversation_with_any_prompt_is_refused_whole() {
        // Positive control, same harness: talk only.
        let talk = MessageLog::default();
        let (code, resp) = converse_with_log(
            &[
                pam_message(PAM_TEXT_INFO, c"before"),
                pam_message(PAM_ERROR_MSG, c"after"),
            ],
            &talk,
            &quiet,
        );
        assert_eq!(
            code, PAM_SUCCESS,
            "control: a call that only talks must pass"
        );
        free_answer(resp, 2);
        assert_eq!(talk.messages(), ["before", "after"], "control");

        for (asking, style) in [
            ("PAM_PROMPT_ECHO_ON", PAM_PROMPT_ECHO_ON),
            ("PAM_PROMPT_ECHO_OFF", PAM_PROMPT_ECHO_OFF),
            ("PAM_RADIO_TYPE", PAM_RADIO_TYPE),
        ] {
            let log = MessageLog::default();
            let (code, resp) = converse_with_log(
                &[
                    pam_message(PAM_TEXT_INFO, c"before"),
                    pam_message(style, c"Login: "),
                    pam_message(PAM_ERROR_MSG, c"after"),
                ],
                &log,
                &quiet,
            );
            assert_eq!(code, PAM_CONV_ERR, "a call with {asking} must be refused");
            assert!(resp.is_null(), "a call with {asking} must allocate nothing");
            assert_eq!(
                log.messages(),
                ["before", "after"],
                "a refused call's messages must still be kept ({asking})"
            );
        }
    }

    /// A call outside PAM's own bounds is refused without being read: no
    /// messages at all, or more than `PAM_MAX_NUM_MSG`.
    #[test]
    fn a_conversation_outside_the_bounds_is_refused() {
        let many: Vec<PamMessage> = (0..=PAM_MAX_NUM_MSG)
            .map(|_| pam_message(PAM_TEXT_INFO, c"line"))
            .collect();
        let most = &many[..PAM_MAX_NUM_MSG as usize];

        // Positive control: exactly the most a call may carry passes.
        let log = MessageLog::default();
        let (code, resp) = converse_with_log(most, &log, &quiet);
        assert_eq!(
            code, PAM_SUCCESS,
            "control: {PAM_MAX_NUM_MSG} messages must pass"
        );
        free_answer(resp, most.len());

        let log = MessageLog::default();
        let (code, resp) = converse_with_log(&many, &log, &quiet);
        assert_eq!(
            (code, resp.is_null()),
            (PAM_CONV_ERR, true),
            "one message past the bound must be refused, allocating nothing"
        );
        assert!(
            log.messages().is_empty(),
            "a call past the bound must not be read"
        );

        let (code, resp) = converse_with_log(&[], &log, &quiet);
        assert_eq!(
            (code, resp.is_null()),
            (PAM_CONV_ERR, true),
            "an empty call must be refused, allocating nothing"
        );
    }

    /// A call with a pointer missing where one is needed, or with a negative
    /// count, is refused without being read -- rather than read through.
    /// Run in a process of its own, so that a conversation function that
    /// does read through one fails this test instead of killing the suite.
    #[test]
    fn a_conversation_with_missing_pointers_is_refused() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::a_conversation_with_missing_pointers_is_refused_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`a_conversation_with_missing_pointers_is_refused`].
    #[test]
    #[ignore = "runs only via a_conversation_with_missing_pointers_is_refused, in a process of its \
                own"]
    fn a_conversation_with_missing_pointers_is_refused_body() {
        let log = MessageLog::default();
        let info = pam_message(PAM_TEXT_INFO, c"line");
        let mut one = [&info as *const PamMessage];
        let mut with_a_hole = [&info as *const PamMessage, ptr::null()];

        // Positive control: the same message, well formed, passes.
        let mut resp: *mut PamResponse = ptr::dangling_mut();
        // SAFETY: one live message; `resp` is writable.
        let code = unsafe {
            converse_logging_to(
                1,
                one.as_mut_ptr(),
                &mut resp,
                log.as_ptr(),
                &quiet,
                libc::calloc,
            )
        };
        assert_eq!(code, PAM_SUCCESS, "control");
        free_answer(resp, 1);
        assert_eq!(log.messages(), ["line"], "control");

        let log = MessageLog::default();
        let refused =
            |num_msg: c_int, msg: *mut *const PamMessage, state: *mut c_void, what: &str| {
                let mut resp: *mut PamResponse = ptr::dangling_mut();
                // SAFETY: each call breaks exactly one part of the contract that
                // the function checks for itself.
                let code = unsafe {
                    converse_logging_to(num_msg, msg, &mut resp, state, &quiet, libc::calloc)
                };
                assert_eq!(
                    (code, resp.is_null()),
                    (PAM_CONV_ERR, true),
                    "{what} must be refused, allocating nothing"
                );
            };
        refused(-1, one.as_mut_ptr(), log.as_ptr(), "a negative count");
        refused(1, ptr::null_mut(), log.as_ptr(), "a NULL message array");
        refused(1, one.as_mut_ptr(), ptr::null_mut(), "a missing state");
        refused(2, with_a_hole.as_mut_ptr(), log.as_ptr(), "a NULL message");
        assert_eq!(
            log.messages(),
            ["line"],
            "only the call with a NULL message may be read, and its other message kept"
        );

        // A message with no text says nothing, and is acknowledged as such.
        let silent = PamMessage {
            msg_style: PAM_TEXT_INFO,
            msg: ptr::null(),
        };
        let mut no_text = [&silent as *const PamMessage];
        let mut resp: *mut PamResponse = ptr::dangling_mut();
        // SAFETY: one live message, with a NULL text.
        let code = unsafe {
            converse_logging_to(
                1,
                no_text.as_mut_ptr(),
                &mut resp,
                log.as_ptr(),
                &quiet,
                libc::calloc,
            )
        };
        assert_eq!(
            code, PAM_SUCCESS,
            "a message with no text must be acknowledged"
        );
        free_answer(resp, 1);
        // SAFETY: as above; there is no answer slot to write to at all.
        let no_answer = unsafe {
            converse_logging_to(
                1,
                one.as_mut_ptr(),
                ptr::null_mut(),
                log.as_ptr(),
                &quiet,
                libc::calloc,
            )
        };
        assert_eq!(
            no_answer, PAM_CONV_ERR,
            "a NULL answer slot must be refused"
        );
        assert_eq!(
            log.messages(),
            ["line", ""],
            "a message with no text must be kept as an empty one"
        );
    }

    /// A panic inside the conversation stays inside it: the call is
    /// refused, nothing is allocated, and the panic never reaches the
    /// caller -- which, in the daemon, is C.
    #[test]
    fn a_panic_inside_the_conversation_does_not_leave_it() {
        let messages = [pam_message(PAM_TEXT_INFO, c"a line")];
        // Positive control, same harness: a logger that works.
        let log = MessageLog::default();
        let (code, resp) = converse_with_log(&messages, &log, &quiet);
        assert_eq!(code, PAM_SUCCESS, "control");
        free_answer(resp, 1);

        let log = MessageLog::default();
        let panicking = |_: c_int, _: &str| panic!("this test's logger panics");
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            converse_with_log(&messages, &log, &panicking)
        }));
        let (code, resp) = outcome.expect("a panic inside the conversation must not leave it");
        assert_eq!(code, PAM_CONV_ERR, "a call that panicked must be refused");
        assert!(resp.is_null(), "a call that panicked must allocate nothing");

        // And a panic whose payload panics again when it is dropped: the
        // payload is dropped outside the catch, so it must not be dropped
        // at all.
        struct PanicsWhenDropped;
        impl Drop for PanicsWhenDropped {
            fn drop(&mut self) {
                panic!("this test's payload panics when it is dropped");
            }
        }
        let log = MessageLog::default();
        let nested = |_: c_int, _: &str| std::panic::panic_any(PanicsWhenDropped);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            converse_with_log(&messages, &log, &nested)
        }));
        let (code, resp) =
            outcome.expect("a payload that panics when dropped must not leave it either");
        assert_eq!(code, PAM_CONV_ERR, "that call must be refused too");
        assert!(resp.is_null(), "and allocate nothing");
    }

    /// Ending a transaction calls `pam_end` -- the modules it loaded are
    /// unloaded -- and forgets the handle, so the `Drop` that follows does
    /// nothing more. Dropping a transaction ends it the same way.
    #[test]
    fn a_transaction_is_ended_once() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::a_transaction_is_ended_once_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// How many mappings of `pam_echo.so` this process has.
    fn pam_echo_mappings() -> usize {
        std::fs::read_to_string("/proc/self/maps")
            .expect("/proc/self/maps")
            .lines()
            .filter(|line| line.ends_with("/pam_echo.so"))
            .count()
    }

    /// Runs only via [`a_transaction_is_ended_once`], in a process of its
    /// own: whether a module is loaded is a property of the whole process,
    /// and no other test's handle may hold it.
    #[test]
    #[ignore = "runs only via a_transaction_is_ended_once, in a process of its own"]
    fn a_transaction_is_ended_once_body() {
        let dir = confdir(&[(
            "qshd-test-echo",
            "auth required pam_permit.so\n\
             account required pam_echo.so\n\
             account required pam_permit.so\n\
             session required pam_permit.so\n",
        )]);
        assert_eq!(
            pam_echo_mappings(),
            0,
            "setup: nothing has loaded pam_echo yet"
        );

        let pam = start_in(dir.path(), "qshd-test-echo");
        assert_ne!(
            pam_echo_mappings(),
            0,
            "control: a started transaction must have loaded pam_echo"
        );
        drop(pam);
        assert_eq!(pam_echo_mappings(), 0, "dropping a transaction must end it");

        let mut pam = start_in(dir.path(), "qshd-test-echo");
        assert_ne!(pam_echo_mappings(), 0, "control: loaded again");
        assert!(pam.end(), "the first end must end the transaction");
        assert_eq!(pam_echo_mappings(), 0, "end must call pam_end");
        assert!(
            pam.handle.is_null(),
            "an ended transaction must forget its handle"
        );
        assert!(!pam.end(), "a second end must do nothing");
        drop(pam);
    }

    /// Module messages, and a contained panic, reach the helper's log; the
    /// real conversation function writes them there.
    #[test]
    fn the_conversation_writes_to_the_helpers_log() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_conversation_writes_to_the_helpers_log_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_conversation_writes_to_the_helpers_log`], in a
    /// process of its own: it points this process's log at a file of its
    /// own, for good.
    #[test]
    #[ignore = "runs only via the_conversation_writes_to_the_helpers_log, in a process of its own"]
    fn the_conversation_writes_to_the_helpers_log_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let log_path = dir.path().join("qshd.log");
        let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
        crate::log::info("qshd", "setup line");
        assert!(
            read_log().contains("setup line"),
            "setup: the log must be writable"
        );

        let state = MessageLog::default();
        let info = pam_message(PAM_TEXT_INFO, c"a word\nand another");
        let error = pam_message(PAM_ERROR_MSG, c"a complaint");
        let mut pointers = [&info as *const PamMessage, &error as *const PamMessage];
        let mut resp: *mut PamResponse = ptr::null_mut();
        // SAFETY: two live messages; `resp` is writable.
        let code = unsafe { converse(2, pointers.as_mut_ptr(), &mut resp, state.as_ptr()) };
        assert_eq!(code, PAM_SUCCESS, "setup: a call that only talks must pass");
        free_answer(resp, 2);
        let log = read_log();
        assert!(
            log.contains(r#"INFO  helper: a PAM module says (info): "a word\nand another""#),
            "an info message must be logged on one line, escaped; the log is:\n{log}"
        );
        assert!(
            log.contains(r#"WARN  helper: a PAM module says (error): "a complaint""#),
            "an error message must be logged as one; the log is:\n{log}"
        );
        assert!(
            !log.contains(CONVERSATION_PANICKED_LOG),
            "setup: no panic yet"
        );

        let panicking = |_: c_int, _: &str| panic!("this test's logger panics");
        let (code, _) = converse_with_log(&[info], &state, &panicking);
        assert_eq!(code, PAM_CONV_ERR, "setup: the panic must be contained");
        let log = read_log();
        assert!(
            log.contains(CONVERSATION_PANICKED_LOG),
            "a contained panic must be logged; the log is:\n{log}"
        );
    }

    /// An answer array that cannot be allocated is a refusal with nothing
    /// handed back -- never PAM_SUCCESS with a NULL array.
    #[test]
    fn an_answer_that_cannot_be_allocated_is_refused() {
        unsafe extern "C" fn out_of_memory(_: usize, _: usize) -> *mut c_void {
            ptr::null_mut()
        }
        let log = MessageLog::default();
        let info = pam_message(PAM_TEXT_INFO, c"line");
        let mut one = [&info as *const PamMessage];
        let mut call = |alloc: AnswerAllocator| {
            let mut resp: *mut PamResponse = ptr::dangling_mut();
            // SAFETY: one live message; `resp` is writable.
            let code = unsafe {
                converse_logging_to(1, one.as_mut_ptr(), &mut resp, log.as_ptr(), &quiet, alloc)
            };
            (code, resp)
        };
        // Positive control, same harness: calloc works, the call passes.
        let (code, resp) = call(libc::calloc);
        assert_eq!(code, PAM_SUCCESS, "control");
        free_answer(resp, 1);

        let (code, resp) = call(out_of_memory);
        assert_eq!(
            (code, resp.is_null()),
            (PAM_BUF_ERR, true),
            "an answer that cannot be allocated must be refused, handing nothing back"
        );
    }

    use crate::test_allocator::{offset_allocations, OFFSET_ENV};

    /// Runs `inner` in a process of its own with the offset allocator on.
    fn run_offset(inner: &str) -> (std::process::ExitStatus, String, String) {
        let on = std::ffi::OsStr::new("1");
        super::super::spawner::tests::run_isolated_with_env(
            inner,
            &[(OFFSET_ENV.to_str().expect("ascii"), on)],
        )
    }

    /// Control for the allocator above: with it on, a Rust allocation
    /// handed to `free()` kills the process.
    #[test]
    fn a_rust_allocation_handed_to_free_is_caught() {
        use std::os::unix::process::ExitStatusExt as _;
        let (status, stdout, stderr) =
            run_offset("helper::pam::tests::a_rust_allocation_handed_to_free_is_caught_body");
        assert_eq!(
            status.signal(),
            Some(nix::libc::SIGABRT),
            "control: the offset allocator must make free() refuse Rust memory ({status}):\n\
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[test]
    #[ignore = "runs only via a_rust_allocation_handed_to_free_is_caught"]
    fn a_rust_allocation_handed_to_free_is_caught_body() {
        if !offset_allocations() {
            return; // run in-process by `--include-ignored`: nothing to show
        }
        let rust = Box::into_raw(Box::new([0u8; 16]));
        // SAFETY: deliberately wrong -- the point of the control.
        unsafe { libc::free(rust.cast()) };
    }

    /// The real conversation hands back an array the library can `free()`,
    /// even when Rust's allocator is not `malloc`.
    #[test]
    fn the_answer_is_the_librarys_to_free() {
        let (status, stdout, stderr) =
            run_offset("helper::pam::tests::the_answer_is_the_librarys_to_free_body");
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[test]
    #[ignore = "runs only via the_answer_is_the_librarys_to_free"]
    fn the_answer_is_the_librarys_to_free_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("motd"), "a word\n").expect("write");
        std::fs::write(
            dir.path().join("qshd-test-echo"),
            format!(
                "auth required pam_permit.so\n\
                 account required pam_echo.so file={}\n\
                 account required pam_permit.so\n\
                 session required pam_permit.so\n",
                dir.path().join("motd").display()
            ),
        )
        .expect("write");
        assert!(
            offset_allocations(),
            "setup: the offset allocator must be on"
        );
        let me = current_account_name();
        let state = MessageLog::default();
        let info = pam_message(PAM_TEXT_INFO, c"line");
        let mut one = [&info as *const PamMessage];
        let mut resp: *mut PamResponse = ptr::null_mut();
        // SAFETY: one live message; `resp` is writable.
        let code = unsafe { converse(1, one.as_mut_ptr(), &mut resp, state.as_ptr()) };
        assert_eq!(code, PAM_SUCCESS, "a call that only talks must pass");
        free_answer(resp, 1);
        // And the library itself frees one, through pam_echo.
        let mut pam = Pam::start_confdir(dir.path(), "qshd-test-echo", &me, "/dev/pts/0", "x")
            .expect("start");
        pam.acct_mgmt().expect("pam_echo admits");
        assert_eq!(pam.messages(), ["a word"], "pam_echo's line");
    }

    /// Listing the environment leaks nothing: neither the strings nor the
    /// array. Run alone, so the heap's growth is this test's.
    #[test]
    fn the_environment_list_leaks_nothing() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::pam::tests::the_environment_list_leaks_nothing_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[test]
    #[ignore = "runs only via the_environment_list_leaks_nothing"]
    fn the_environment_list_leaks_nothing_body() {
        const ROUNDS: usize = 1000;
        const NOISE: usize = 8 * 1024;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("env"),
            "QSHD_PAM_TEST DEFAULT=from-the-stack\n",
        )
        .expect("write");
        std::fs::write(
            dir.path().join("qshd-test-env"),
            format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_env.so conffile={} envfile=/dev/null readenv=0\n\
                 session required pam_permit.so\n",
                dir.path().join("env").display()
            ),
        )
        .expect("write");
        let mut pam = start_in(dir.path(), "qshd-test-env");
        pam.open_session().expect("open");
        // SAFETY: plain query.
        let in_use = || unsafe { libc::mallinfo2() }.uordblks;
        assert_eq!(pam.env_list().len(), 1, "setup: one variable");

        // Positive control, same meter: a leak as small as one 16-byte
        // array per round shows.
        let mut kept = Vec::with_capacity(ROUNDS);
        let before = in_use();
        for _ in 0..ROUNDS {
            // SAFETY: plain allocation, kept on purpose and freed below.
            kept.push(unsafe { libc::malloc(16) });
        }
        let grown = in_use().saturating_sub(before);
        assert!(
            grown > NOISE,
            "control: a 16 KB leak must show, grew {grown}"
        );
        for p in kept {
            // SAFETY: each came from malloc above.
            unsafe { libc::free(p) };
        }

        let before = in_use();
        for _ in 0..ROUNDS {
            drop(pam.env_list());
        }
        let grown = in_use().saturating_sub(before);
        assert!(
            grown < NOISE,
            "listing the environment {ROUNDS} times must not grow the heap, grew {grown} bytes"
        );

        // The same for a whole transaction: its conversation state is freed
        // with it. Starting one loads and unloads modules, and that leaves a
        // few bytes behind each time (about 9 bytes a round here, some of it
        // the dynamic loader's own bookkeeping), so this round is measured
        // against a looser bound -- still far below the ~32 bytes a round a
        // leaked conversation state would add.
        const TRANSACTION_NOISE: usize = 20 * 1024;
        let before = in_use();
        for _ in 0..ROUNDS {
            drop(start_in(dir.path(), "qshd-test-env"));
        }
        let grown = in_use().saturating_sub(before);
        assert!(
            grown < TRANSACTION_NOISE,
            "starting and ending {ROUNDS} transactions must not grow the heap, grew {grown} bytes"
        );
    }
}
