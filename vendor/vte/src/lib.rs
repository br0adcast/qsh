//! Parser for implementing virtual terminal emulators
//!
//! [`Parser`] is implemented according to [Paul Williams' ANSI parser state
//! machine]. The state machine doesn't assign meaning to the parsed data and is
//! thus not itself sufficient for writing a terminal emulator. Instead, it is
//! expected that an implementation of [`Perform`] is provided which does
//! something useful with the parsed data. The [`Parser`] handles the book
//! keeping, and the [`Perform`] gets to simply handle actions.
//!
//! # Examples
//!
//! For an example of using the [`Parser`] please see the examples folder. The
//! example included there simply logs all the actions [`Perform`] does. One
//! quick way to see it in action is to pipe `printf` into it
//!
//! ```sh
//! printf '\x1b[31mExample' | cargo run --example parselog
//! ```
//!
//! # Differences from original state machine description
//!
//! * UTF-8 Support for Input
//! * OSC Strings can be terminated by 0x07
//! * Only supports 7-bit codes
//!
//! [`Parser`]: struct.Parser.html
//! [`Perform`]: trait.Perform.html
//! [Paul Williams' ANSI parser state machine]: https://vt100.net/emu/dec_ansi_parser
#![deny(clippy::all, clippy::if_not_else, clippy::enum_glob_use)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::mem::MaybeUninit;
use core::str;

#[cfg(not(feature = "std"))]
use arrayvec::ArrayVec;

mod params;

#[cfg(feature = "ansi")]
pub mod ansi;
pub use params::{Params, ParamsIter};

const MAX_INTERMEDIATES: usize = 2;
const MAX_OSC_PARAMS: usize = 16;
const MAX_OSC_RAW: usize = 1024;

/// Parser for raw _VTE_ protocol which delegates actions to a [`Perform`]
///
/// [`Perform`]: trait.Perform.html
///
/// Generic over the value for the size of the raw Operating System Command
/// buffer. Only used when the `std` feature is not enabled.
#[derive(Default)]
pub struct Parser<const OSC_RAW_BUF_SIZE: usize = MAX_OSC_RAW> {
    state: State,
    intermediates: [u8; MAX_INTERMEDIATES],
    intermediate_idx: usize,
    params: Params,
    param: u16,
    #[cfg(not(feature = "std"))]
    osc_raw: ArrayVec<u8, OSC_RAW_BUF_SIZE>,
    #[cfg(feature = "std")]
    osc_raw: Vec<u8>,
    osc_params: [(usize, usize); MAX_OSC_PARAMS],
    osc_num_params: usize,
    // Count separators too: they are not stored in osc_raw.
    #[cfg(feature = "std")]
    osc_bytes: usize,
    ignoring: bool,
    partial_utf8: [u8; 4],
    partial_utf8_len: usize,
}

impl Parser {
    /// Create a new Parser
    pub fn new() -> Parser {
        Default::default()
    }
}

impl<const OSC_RAW_BUF_SIZE: usize> Parser<OSC_RAW_BUF_SIZE> {
    /// Create a new Parser with a custom size for the Operating System Command
    /// buffer.
    ///
    /// Call with a const-generic param on `Parser`, like:
    ///
    /// ```rust
    /// let mut p = vte::Parser::<64>::new_with_size();
    /// ```
    #[cfg(not(feature = "std"))]
    pub fn new_with_size() -> Parser<OSC_RAW_BUF_SIZE> {
        Default::default()
    }

    #[inline]
    fn params(&self) -> &Params {
        &self.params
    }

    #[inline]
    fn intermediates(&self) -> &[u8] {
        &self.intermediates[..self.intermediate_idx]
    }

    /// Advance the parser state.
    ///
    /// Requires a [`Perform`] implementation to handle the triggered actions.
    ///
    /// [`Perform`]: trait.Perform.html
    #[inline]
    pub fn advance<P: Perform>(&mut self, performer: &mut P, bytes: &[u8]) {
        let mut i = 0;

        // Handle partial codepoints from previous calls to `advance`.
        if self.partial_utf8_len != 0 {
            i += self.advance_partial_utf8(performer, bytes);
        }

        while i != bytes.len() {
            match self.state {
                State::Ground => i += self.advance_ground(performer, &bytes[i..]),
                _ => {
                    // Inlining it results in worse codegen.
                    let byte = bytes[i];
                    self.change_state(performer, byte);
                    i += 1;
                },
            }
        }
    }

    /// Partially advance the parser state.
    ///
    /// This is equivalent to [`Self::advance`], but stops when
    /// [`Perform::terminated`] is true after reading a byte.
    ///
    /// Returns the number of bytes read before termination.
    ///
    /// See [`Perform::advance`] for more details.
    #[inline]
    #[must_use = "Returned value should be used to processs the remaining bytes"]
    pub fn advance_until_terminated<P: Perform>(
        &mut self,
        performer: &mut P,
        bytes: &[u8],
    ) -> usize {
        let mut i = 0;

        // Handle partial codepoints from previous calls to `advance`.
        if self.partial_utf8_len != 0 {
            i += self.advance_partial_utf8(performer, bytes);
        }

        while i != bytes.len() && !performer.terminated() {
            match self.state {
                State::Ground => i += self.advance_ground(performer, &bytes[i..]),
                _ => {
                    // Inlining it results in worse codegen.
                    let byte = bytes[i];
                    self.change_state(performer, byte);
                    i += 1;
                },
            }
        }

        i
    }

    #[inline(always)]
    fn change_state<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match self.state {
            State::CsiEntry => self.advance_csi_entry(performer, byte),
            State::CsiIgnore => self.advance_csi_ignore(performer, byte),
            State::CsiIntermediate => self.advance_csi_intermediate(performer, byte),
            State::CsiParam => self.advance_csi_param(performer, byte),
            State::DcsEntry => self.advance_dcs_entry(performer, byte),
            State::DcsIgnore => self.anywhere(performer, byte),
            State::DcsIntermediate => self.advance_dcs_intermediate(performer, byte),
            State::DcsParam => self.advance_dcs_param(performer, byte),
            State::DcsPassthrough => self.advance_dcs_passthrough(performer, byte),
            State::Escape => self.advance_esc(performer, byte),
            State::EscapeIntermediate => self.advance_esc_intermediate(performer, byte),
            State::OscString => self.advance_osc_string(performer, byte),
            State::SosPmApcString => self.anywhere(performer, byte),
            State::Ground => unreachable!(),
        }
    }

    #[inline(always)]
    fn advance_csi_entry<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => performer.execute(byte),
            0x20..=0x2F => {
                self.action_collect(byte);
                self.state = State::CsiIntermediate
            },
            0x30..=0x39 => {
                self.action_paramnext(byte);
                self.state = State::CsiParam
            },
            0x3A => {
                self.action_subparam();
                self.state = State::CsiParam
            },
            0x3B => {
                self.action_param();
                self.state = State::CsiParam
            },
            0x3C..=0x3F => {
                self.action_collect(byte);
                self.state = State::CsiParam
            },
            0x40..=0x7E => self.action_csi_dispatch(performer, byte),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_csi_ignore<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => performer.execute(byte),
            0x20..=0x3F => (),
            0x40..=0x7E => self.state = State::Ground,
            0x7F => (),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_csi_intermediate<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => performer.execute(byte),
            0x20..=0x2F => self.action_collect(byte),
            0x30..=0x3F => self.state = State::CsiIgnore,
            0x40..=0x7E => self.action_csi_dispatch(performer, byte),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_csi_param<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => performer.execute(byte),
            0x20..=0x2F => {
                self.action_collect(byte);
                self.state = State::CsiIntermediate
            },
            0x30..=0x39 => self.action_paramnext(byte),
            0x3A => self.action_subparam(),
            0x3B => self.action_param(),
            0x3C..=0x3F => self.state = State::CsiIgnore,
            0x40..=0x7E => self.action_csi_dispatch(performer, byte),
            0x7F => (),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_dcs_entry<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => (),
            0x20..=0x2F => {
                self.action_collect(byte);
                self.state = State::DcsIntermediate
            },
            0x30..=0x39 => {
                self.action_paramnext(byte);
                self.state = State::DcsParam
            },
            0x3A => {
                self.action_subparam();
                self.state = State::DcsParam
            },
            0x3B => {
                self.action_param();
                self.state = State::DcsParam
            },
            0x3C..=0x3F => {
                self.action_collect(byte);
                self.state = State::DcsParam
            },
            0x40..=0x7E => self.action_hook(performer, byte),
            0x7F => (),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_dcs_intermediate<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => (),
            0x20..=0x2F => self.action_collect(byte),
            0x30..=0x3F => self.state = State::DcsIgnore,
            0x40..=0x7E => self.action_hook(performer, byte),
            0x7F => (),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_dcs_param<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => (),
            0x20..=0x2F => {
                self.action_collect(byte);
                self.state = State::DcsIntermediate
            },
            0x30..=0x39 => self.action_paramnext(byte),
            0x3A => self.action_subparam(),
            0x3B => self.action_param(),
            0x3C..=0x3F => self.state = State::DcsIgnore,
            0x40..=0x7E => self.action_hook(performer, byte),
            0x7F => (),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_dcs_passthrough<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x7E => performer.put(byte),
            0x18 | 0x1A => {
                performer.unhook();
                performer.execute(byte);
                self.state = State::Ground
            },
            0x1B => {
                performer.unhook();
                self.reset_params();
                self.state = State::Escape
            },
            0x7F => (),
            0x9C => {
                performer.unhook();
                self.state = State::Ground
            },
            _ => (),
        }
    }

    #[inline(always)]
    fn advance_esc<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => performer.execute(byte),
            0x20..=0x2F => {
                self.action_collect(byte);
                self.state = State::EscapeIntermediate
            },
            0x30..=0x4F => {
                performer.esc_dispatch(self.intermediates(), self.ignoring, byte);
                self.state = State::Ground
            },
            0x50 => {
                self.reset_params();
                self.state = State::DcsEntry
            },
            0x51..=0x57 => {
                performer.esc_dispatch(self.intermediates(), self.ignoring, byte);
                self.state = State::Ground
            },
            0x58 => self.state = State::SosPmApcString,
            0x59..=0x5A => {
                performer.esc_dispatch(self.intermediates(), self.ignoring, byte);
                self.state = State::Ground
            },
            0x5B => {
                self.reset_params();
                self.state = State::CsiEntry
            },
            0x5C => {
                performer.esc_dispatch(self.intermediates(), self.ignoring, byte);
                self.state = State::Ground
            },
            0x5D => {
                self.osc_raw.clear();
                self.osc_num_params = 0;
                #[cfg(feature = "std")]
                { self.osc_bytes = 0; }
                self.state = State::OscString
            },
            0x5E..=0x5F => self.state = State::SosPmApcString,
            0x60..=0x7E => {
                performer.esc_dispatch(self.intermediates(), self.ignoring, byte);
                self.state = State::Ground
            },
            // Anywhere.
            0x18 | 0x1A => {
                performer.execute(byte);
                self.state = State::Ground
            },
            0x1B => (),
            _ => (),
        }
    }

    #[inline(always)]
    fn advance_esc_intermediate<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x00..=0x17 | 0x19 | 0x1C..=0x1F => performer.execute(byte),
            0x20..=0x2F => self.action_collect(byte),
            0x30..=0x7E => {
                performer.esc_dispatch(self.intermediates(), self.ignoring, byte);
                self.state = State::Ground
            },
            0x7F => (),
            _ => self.anywhere(performer, byte),
        }
    }

    #[inline(always)]
    fn advance_osc_string<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        #[cfg(feature = "std")]
        if byte >= 0x20 {
            // Overflow discards the whole command; keep consuming through
            // the existing state machine until its normal termination.
            self.osc_bytes = (self.osc_bytes + 1).min(8193);
            if self.osc_bytes > 8192 { return; }
        }
        match byte {
            0x00..=0x06 | 0x08..=0x17 | 0x19 | 0x1C..=0x1F => (),
            0x07 => {
                self.osc_end(performer, byte);
                self.state = State::Ground
            },
            0x18 | 0x1A => {
                self.osc_end(performer, byte);
                performer.execute(byte);
                self.state = State::Ground
            },
            0x1B => {
                self.osc_end(performer, byte);
                self.reset_params();
                self.state = State::Escape
            },
            0x3B => {
                #[cfg(not(feature = "std"))]
                {
                    if self.osc_raw.is_full() {
                        return;
                    }
                }
                self.action_osc_put_param()
            },
            _ => self.action_osc_put(byte),
        }
    }

    #[inline(always)]
    fn anywhere<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        match byte {
            0x18 | 0x1A => {
                performer.execute(byte);
                self.state = State::Ground
            },
            0x1B => {
                self.reset_params();
                self.state = State::Escape
            },
            _ => (),
        }
    }

    #[inline]
    fn action_csi_dispatch<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        if self.params.is_full() {
            self.ignoring = true;
        } else {
            self.params.push(self.param);
        }
        performer.csi_dispatch(self.params(), self.intermediates(), self.ignoring, byte as char);

        self.state = State::Ground
    }

    #[inline]
    fn action_hook<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        if self.params.is_full() {
            self.ignoring = true;
        } else {
            self.params.push(self.param);
        }
        performer.hook(self.params(), self.intermediates(), self.ignoring, byte as char);
        self.state = State::DcsPassthrough;
    }

    #[inline]
    fn action_collect(&mut self, byte: u8) {
        if self.intermediate_idx == MAX_INTERMEDIATES {
            self.ignoring = true;
        } else {
            self.intermediates[self.intermediate_idx] = byte;
            self.intermediate_idx += 1;
        }
    }

    /// Advance to the next subparameter.
    #[inline]
    fn action_subparam(&mut self) {
        if self.params.is_full() {
            self.ignoring = true;
        } else {
            self.params.extend(self.param);
            self.param = 0;
        }
    }

    /// Advance to the next parameter.
    #[inline]
    fn action_param(&mut self) {
        if self.params.is_full() {
            self.ignoring = true;
        } else {
            self.params.push(self.param);
            self.param = 0;
        }
    }

    /// Advance inside the parameter without terminating it.
    #[inline]
    fn action_paramnext(&mut self, byte: u8) {
        if self.params.is_full() {
            self.ignoring = true;
        } else {
            // Continue collecting bytes into param.
            self.param = self.param.saturating_mul(10);
            self.param = self.param.saturating_add((byte - b'0') as u16);
        }
    }

    /// Add OSC param separator.
    #[inline]
    fn action_osc_put_param(&mut self) {
        let idx = self.osc_raw.len();

        let param_idx = self.osc_num_params;
        match param_idx {
            // First param is special - 0 to current byte index.
            0 => self.osc_params[param_idx] = (0, idx),

            // Only process up to MAX_OSC_PARAMS.
            MAX_OSC_PARAMS => return,

            // All other params depend on previous indexing.
            _ => {
                let prev = self.osc_params[param_idx - 1];
                let begin = prev.1;
                self.osc_params[param_idx] = (begin, idx);
            },
        }

        self.osc_num_params += 1;
    }

    #[inline(always)]
    fn action_osc_put(&mut self, byte: u8) {
        #[cfg(not(feature = "std"))]
        {
            if self.osc_raw.is_full() {
                return;
            }
        }
        self.osc_raw.push(byte);
    }

    fn osc_end<P: Perform>(&mut self, performer: &mut P, byte: u8) {
        #[cfg(feature = "std")]
        let dispatch = self.osc_bytes <= 8192;
        #[cfg(not(feature = "std"))]
        let dispatch = true;
        if dispatch {
            self.action_osc_put_param();
            self.osc_dispatch(performer, byte);
        }
        self.osc_raw.clear();
        self.osc_num_params = 0;
    }

    /// Reset escape sequence parameters and intermediates.
    #[inline]
    fn reset_params(&mut self) {
        self.intermediate_idx = 0;
        self.ignoring = false;
        self.param = 0;

        self.params.clear();
    }

    /// Separate method for osc_dispatch that borrows self as read-only
    ///
    /// The aliasing is needed here for multiple slices into self.osc_raw
    #[inline]
    fn osc_dispatch<P: Perform>(&self, performer: &mut P, byte: u8) {
        let mut slices: [MaybeUninit<&[u8]>; MAX_OSC_PARAMS] =
            unsafe { MaybeUninit::uninit().assume_init() };

        for (i, slice) in slices.iter_mut().enumerate().take(self.osc_num_params) {
            let indices = self.osc_params[i];
            *slice = MaybeUninit::new(&self.osc_raw[indices.0..indices.1]);
        }

        unsafe {
            let num_params = self.osc_num_params;
            let params = &slices[..num_params] as *const [MaybeUninit<&[u8]>] as *const [&[u8]];
            performer.osc_dispatch(&*params, byte == 0x07);
        }
    }

    /// Advance the parser state from ground.
    ///
    /// The ground state is handled separately since it can only be left using
    /// the escape character (`\x1b`). This allows more efficient parsing by
    /// using SIMD search with [`memchr`].
    #[inline]
    fn advance_ground<P: Perform>(&mut self, performer: &mut P, bytes: &[u8]) -> usize {
        // Find the next escape character.
        let num_bytes = bytes.len();
        let plain_chars = memchr::memchr(0x1B, bytes).unwrap_or(num_bytes);

        // If the next character is ESC, just process it and short-circuit.
        if plain_chars == 0 {
            self.state = State::Escape;
            self.reset_params();
            return 1;
        }

        match str::from_utf8(&bytes[..plain_chars]) {
            Ok(parsed) => {
                Self::ground_dispatch(performer, parsed);
                let mut processed = plain_chars;

                // If there's another character, it must be escape so process it directly.
                if processed < num_bytes {
                    self.state = State::Escape;
                    self.reset_params();
                    processed += 1;
                }

                processed
            },
            // Handle invalid and partial utf8.
            Err(err) => {
                // Dispatch all the valid bytes.
                let valid_bytes = err.valid_up_to();
                let parsed = unsafe { str::from_utf8_unchecked(&bytes[..valid_bytes]) };
                Self::ground_dispatch(performer, parsed);

                match err.error_len() {
                    Some(len) => {
                        // Execute C1 escapes or emit replacement character.
                        if len == 1 && bytes[valid_bytes] <= 0x9F {
                            performer.execute(bytes[valid_bytes]);
                        } else {
                            performer.print('�');
                        }

                        // Restart processing after the invalid bytes.
                        //
                        // While we could theoretically try to just re-parse
                        // `bytes[valid_bytes + len..plain_chars]`, it's easier
                        // to just skip it and invalid utf8 is pretty rare anyway.
                        valid_bytes + len
                    },
                    None => {
                        if plain_chars < num_bytes {
                            // Process bytes cut off by escape.
                            performer.print('�');
                            self.state = State::Escape;
                            self.reset_params();
                            plain_chars + 1
                        } else {
                            // Process bytes cut off by the buffer end.
                            let extra_bytes = num_bytes - valid_bytes;
                            let partial_len = self.partial_utf8_len + extra_bytes;
                            self.partial_utf8[self.partial_utf8_len..partial_len]
                                .copy_from_slice(&bytes[valid_bytes..valid_bytes + extra_bytes]);
                            self.partial_utf8_len = partial_len;
                            num_bytes
                        }
                    },
                }
            },
        }
    }

    /// Advance the parser while processing a partial utf8 codepoint.
    #[inline]
    fn advance_partial_utf8<P: Perform>(&mut self, performer: &mut P, bytes: &[u8]) -> usize {
        // Try to copy up to 3 more characters, to ensure the codepoint is complete.
        let old_bytes = self.partial_utf8_len;
        let to_copy = bytes.len().min(self.partial_utf8.len() - old_bytes);
        self.partial_utf8[old_bytes..old_bytes + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.partial_utf8_len += to_copy;

        // Parse the unicode character.
        match str::from_utf8(&self.partial_utf8[..self.partial_utf8_len]) {
            // If the entire buffer is valid, use the first character and continue parsing.
            Ok(parsed) => {
                let c = unsafe { parsed.chars().next().unwrap_unchecked() };
                // qsh: a C1 control completed here executes, as it does unsplit.
                Self::ground_dispatch(performer, c.encode_utf8(&mut [0; 4]));

                self.partial_utf8_len = 0;
                c.len_utf8() - old_bytes
            },
            Err(err) => {
                let valid_bytes = err.valid_up_to();
                // If we have any valid bytes, that means we partially copied another
                // utf8 character into `partial_utf8`. Since we only care about the
                // first character, we just ignore the rest.
                if valid_bytes > 0 {
                    let c = unsafe {
                        let parsed = str::from_utf8_unchecked(&self.partial_utf8[..valid_bytes]);
                        parsed.chars().next().unwrap_unchecked()
                    };

                    Self::ground_dispatch(performer, c.encode_utf8(&mut [0; 4]));

                    self.partial_utf8_len = 0;
                    // qsh: consume only the first character. The valid prefix can
                    // hold more characters, which the caller must still parse.
                    return c.len_utf8() - old_bytes;
                }

                match err.error_len() {
                    // If the partial character was also invalid, emit the replacement
                    // character.
                    Some(invalid_len) => {
                        performer.print('�');

                        self.partial_utf8_len = 0;
                        invalid_len - old_bytes
                    },
                    // If the character still isn't complete, wait for more data.
                    None => to_copy,
                }
            },
        }
    }

    /// Handle ground dispatch of print/execute for all characters in a string.
    #[inline]
    fn ground_dispatch<P: Perform>(performer: &mut P, text: &str) {
        for c in text.chars() {
            match c {
                '\x00'..='\x1f' | '\u{80}'..='\u{9f}' => performer.execute(c as u8),
                _ => performer.print(c),
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
enum State {
    CsiEntry,
    CsiIgnore,
    CsiIntermediate,
    CsiParam,
    DcsEntry,
    DcsIgnore,
    DcsIntermediate,
    DcsParam,
    DcsPassthrough,
    Escape,
    EscapeIntermediate,
    OscString,
    SosPmApcString,
    #[default]
    Ground,
}

/// Performs actions requested by the Parser
///
/// Actions in this case mean, for example, handling a CSI escape sequence
/// describing cursor movement, or simply printing characters to the screen.
///
/// The methods on this type correspond to actions described in
/// <http://vt100.net/emu/dec_ansi_parser>. I've done my best to describe them in
/// a useful way in my own words for completeness, but the site should be
/// referenced if something isn't clear. If the site disappears at some point in
/// the future, consider checking archive.org.
pub trait Perform {
    /// Draw a character to the screen and update states.
    fn print(&mut self, _c: char) {}

    /// Execute a C0 or C1 control function.
    fn execute(&mut self, _byte: u8) {}

    /// Invoked when a final character arrives in first part of device control
    /// string.
    ///
    /// The control function should be determined from the private marker, final
    /// character, and execute with a parameter list. A handler should be
    /// selected for remaining characters in the string; the handler
    /// function should subsequently be called by `put` for every character in
    /// the control string.
    ///
    /// The `ignore` flag indicates that more than two intermediates arrived and
    /// subsequent characters were ignored.
    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {}

    /// Pass bytes as part of a device control string to the handle chosen in
    /// `hook`. C0 controls will also be passed to the handler.
    fn put(&mut self, _byte: u8) {}

    /// Called when a device control string is terminated.
    ///
    /// The previously selected handler should be notified that the DCS has
    /// terminated.
    fn unhook(&mut self) {}

    /// Dispatch an operating system command.
    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {}

    /// A final character has arrived for a CSI sequence
    ///
    /// The `ignore` flag indicates that either more than two intermediates
    /// arrived or the number of parameters exceeded the maximum supported
    /// length, and subsequent characters were ignored.
    fn csi_dispatch(
        &mut self,
        _params: &Params,
        _intermediates: &[u8],
        _ignore: bool,
        _action: char,
    ) {
    }

    /// The final character of an escape sequence has arrived.
    ///
    /// The `ignore` flag indicates that more than two intermediates arrived and
    /// subsequent characters were ignored.
    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {}

    /// Whether the parser should terminate prematurely.
    ///
    /// This can be used in conjunction with
    /// [`Parser::advance_until_terminated`] to terminate the parser after
    /// receiving certain escape sequences like synchronized updates.
    ///
    /// This is checked after every parsed byte, so no expensive computation
    /// should take place in this function.
    #[inline(always)]
    fn terminated(&self) -> bool {
        false
    }
}

#[cfg(all(test, not(feature = "std")))]
#[macro_use]
extern crate std;

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    const OSC_BYTES: &[u8] = &[
        0x1B, 0x5D, // Begin OSC
        b'2', b';', b'j', b'w', b'i', b'l', b'm', b'@', b'j', b'w', b'i', b'l', b'm', b'-', b'd',
        b'e', b's', b'k', b':', b' ', b'~', b'/', b'c', b'o', b'd', b'e', b'/', b'a', b'l', b'a',
        b'c', b'r', b'i', b't', b't', b'y', 0x07, // End OSC
    ];

    #[derive(Default)]
    struct Dispatcher {
        dispatched: Vec<Sequence>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Sequence {
        Osc(Vec<Vec<u8>>, bool),
        Csi(Vec<Vec<u16>>, Vec<u8>, bool, char),
        Esc(Vec<u8>, bool, u8),
        DcsHook(Vec<Vec<u16>>, Vec<u8>, bool, char),
        DcsPut(u8),
        Print(char),
        Execute(u8),
        DcsUnhook,
    }

    impl Perform for Dispatcher {
        fn osc_dispatch(&mut self, params: &[&[u8]], bell_terminated: bool) {
            let params = params.iter().map(|p| p.to_vec()).collect();
            self.dispatched.push(Sequence::Osc(params, bell_terminated));
        }

        fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], ignore: bool, c: char) {
            let params = params.iter().map(|subparam| subparam.to_vec()).collect();
            let intermediates = intermediates.to_vec();
            self.dispatched.push(Sequence::Csi(params, intermediates, ignore, c));
        }

        fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
            let intermediates = intermediates.to_vec();
            self.dispatched.push(Sequence::Esc(intermediates, ignore, byte));
        }

        fn hook(&mut self, params: &Params, intermediates: &[u8], ignore: bool, c: char) {
            let params = params.iter().map(|subparam| subparam.to_vec()).collect();
            let intermediates = intermediates.to_vec();
            self.dispatched.push(Sequence::DcsHook(params, intermediates, ignore, c));
        }

        fn put(&mut self, byte: u8) {
            self.dispatched.push(Sequence::DcsPut(byte));
        }

        fn unhook(&mut self) {
            self.dispatched.push(Sequence::DcsUnhook);
        }

        fn print(&mut self, c: char) {
            self.dispatched.push(Sequence::Print(c));
        }

        fn execute(&mut self, byte: u8) {
            self.dispatched.push(Sequence::Execute(byte));
        }
    }

    #[test]
    fn parse_osc() {
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, OSC_BYTES);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(params, _) => {
                assert_eq!(params.len(), 2);
                assert_eq!(params[0], &OSC_BYTES[2..3]);
                assert_eq!(params[1], &OSC_BYTES[4..(OSC_BYTES.len() - 1)]);
            },
            _ => panic!("expected osc sequence"),
        }
    }

    #[test]
    fn parse_empty_osc() {
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &[0x1B, 0x5D, 0x07]);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(..) => (),
            _ => panic!("expected osc sequence"),
        }
    }

    #[test]
    fn parse_osc_max_params() {
        let params = ";".repeat(params::MAX_PARAMS + 1);
        let input = format!("\x1b]{}\x1b", &params[..]).into_bytes();
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &input);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(params, _) => {
                assert_eq!(params.len(), MAX_OSC_PARAMS);
                assert!(params.iter().all(Vec::is_empty));
            },
            _ => panic!("expected osc sequence"),
        }
    }

    #[test]
    fn osc_bell_terminated() {
        const INPUT: &[u8] = b"\x1b]11;ff/00/ff\x07";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(_, true) => (),
            _ => panic!("expected osc with bell terminator"),
        }
    }

    #[test]
    fn osc_c0_st_terminated() {
        const INPUT: &[u8] = b"\x1b]11;ff/00/ff\x1b\\";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 2);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(_, false) => (),
            _ => panic!("expected osc with ST terminator"),
        }
    }

    #[test]
    fn parse_osc_with_utf8_arguments() {
        const INPUT: &[u8] = &[
            0x0D, 0x1B, 0x5D, 0x32, 0x3B, 0x65, 0x63, 0x68, 0x6F, 0x20, 0x27, 0xC2, 0xAF, 0x5C,
            0x5F, 0x28, 0xE3, 0x83, 0x84, 0x29, 0x5F, 0x2F, 0xC2, 0xAF, 0x27, 0x20, 0x26, 0x26,
            0x20, 0x73, 0x6C, 0x65, 0x65, 0x70, 0x20, 0x31, 0x07,
        ];
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched[0], Sequence::Execute(b'\r'));
        let osc_data = INPUT[5..(INPUT.len() - 1)].into();
        assert_eq!(dispatcher.dispatched[1], Sequence::Osc(vec![vec![b'2'], osc_data], true));
        assert_eq!(dispatcher.dispatched.len(), 2);
    }

    #[test]
    fn osc_containing_string_terminator() {
        const INPUT: &[u8] = b"\x1b]2;\xe6\x9c\xab\x1b\\";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 2);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(params, _) => {
                assert_eq!(params[1], &INPUT[4..(INPUT.len() - 2)]);
            },
            _ => panic!("expected osc sequence"),
        }
    }

    #[test]
    fn exceed_max_buffer_size() {
        const NUM_BYTES: usize = MAX_OSC_RAW + 100;
        const INPUT_START: &[u8] = b"\x1b]52;s";
        const INPUT_END: &[u8] = b"\x07";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        // Create valid OSC escape
        parser.advance(&mut dispatcher, INPUT_START);

        // Exceed max buffer size
        parser.advance(&mut dispatcher, &[b'a'; NUM_BYTES]);

        // Terminate escape for dispatch
        parser.advance(&mut dispatcher, INPUT_END);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(params, _) => {
                assert_eq!(params.len(), 2);
                assert_eq!(params[0], b"52");

                #[cfg(feature = "std")]
                assert_eq!(params[1].len(), NUM_BYTES + INPUT_END.len());

                #[cfg(not(feature = "std"))]
                assert_eq!(params[1].len(), MAX_OSC_RAW - params[0].len());
            },
            _ => panic!("expected osc sequence"),
        }
    }

    #[test]
    fn parse_csi_max_params() {
        // This will build a list of repeating '1;'s
        // The length is MAX_PARAMS - 1 because the last semicolon is interpreted
        // as an implicit zero, making the total number of parameters MAX_PARAMS
        let params = "1;".repeat(params::MAX_PARAMS - 1);
        let input = format!("\x1b[{}p", &params[..]).into_bytes();

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &input);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, _, ignore, _) => {
                assert_eq!(params.len(), params::MAX_PARAMS);
                assert!(!ignore);
            },
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn parse_csi_params_ignore_long_params() {
        // This will build a list of repeating '1;'s
        // The length is MAX_PARAMS because the last semicolon is interpreted
        // as an implicit zero, making the total number of parameters MAX_PARAMS + 1
        let params = "1;".repeat(params::MAX_PARAMS);
        let input = format!("\x1b[{}p", &params[..]).into_bytes();

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &input);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, _, ignore, _) => {
                assert_eq!(params.len(), params::MAX_PARAMS);
                assert!(ignore);
            },
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn parse_csi_params_trailing_semicolon() {
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, b"\x1b[4;m");

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, ..) => assert_eq!(params, &[[4], [0]]),
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn parse_csi_params_leading_semicolon() {
        // Create dispatcher and check state
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, b"\x1b[;4m");

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, ..) => assert_eq!(params, &[[0], [4]]),
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn parse_long_csi_param() {
        // The important part is the parameter, which is (i64::MAX + 1)
        const INPUT: &[u8] = b"\x1b[9223372036854775808m";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, ..) => assert_eq!(params, &[[u16::MAX]]),
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn csi_reset() {
        const INPUT: &[u8] = b"\x1b[3;1\x1b[?1049h";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, intermediates, ignore, _) => {
                assert_eq!(intermediates, b"?");
                assert_eq!(params, &[[1049]]);
                assert!(!ignore);
            },
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn csi_subparameters() {
        const INPUT: &[u8] = b"\x1b[38:2:255:0:255;1m";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, intermediates, ignore, _) => {
                assert_eq!(params, &[vec![38, 2, 255, 0, 255], vec![1]]);
                assert_eq!(intermediates, &[]);
                assert!(!ignore);
            },
            _ => panic!("expected csi sequence"),
        }
    }

    #[test]
    fn parse_dcs_max_params() {
        let params = "1;".repeat(params::MAX_PARAMS + 1);
        let input = format!("\x1bP{}p", &params[..]).into_bytes();
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &input);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::DcsHook(params, _, ignore, _) => {
                assert_eq!(params.len(), params::MAX_PARAMS);
                assert!(params.iter().all(|param| param == &[1]));
                assert!(ignore);
            },
            _ => panic!("expected dcs sequence"),
        }
    }

    #[test]
    fn dcs_reset() {
        const INPUT: &[u8] = b"\x1b[3;1\x1bP1$tx\x9c";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 3);
        match &dispatcher.dispatched[0] {
            Sequence::DcsHook(params, intermediates, ignore, _) => {
                assert_eq!(intermediates, b"$");
                assert_eq!(params, &[[1]]);
                assert!(!ignore);
            },
            _ => panic!("expected dcs sequence"),
        }
        assert_eq!(dispatcher.dispatched[1], Sequence::DcsPut(b'x'));
        assert_eq!(dispatcher.dispatched[2], Sequence::DcsUnhook);
    }

    #[test]
    fn parse_dcs() {
        const INPUT: &[u8] = b"\x1bP0;1|17/ab\x9c";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 7);
        match &dispatcher.dispatched[0] {
            Sequence::DcsHook(params, _, _, c) => {
                assert_eq!(params, &[[0], [1]]);
                assert_eq!(c, &'|');
            },
            _ => panic!("expected dcs sequence"),
        }
        for (i, byte) in b"17/ab".iter().enumerate() {
            assert_eq!(dispatcher.dispatched[1 + i], Sequence::DcsPut(*byte));
        }
        assert_eq!(dispatcher.dispatched[6], Sequence::DcsUnhook);
    }

    #[test]
    fn intermediate_reset_on_dcs_exit() {
        const INPUT: &[u8] = b"\x1bP=1sZZZ\x1b+\x5c";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 6);
        match &dispatcher.dispatched[5] {
            Sequence::Esc(intermediates, ..) => assert_eq!(intermediates, b"+"),
            _ => panic!("expected esc sequence"),
        }
    }

    #[test]
    fn esc_reset() {
        const INPUT: &[u8] = b"\x1b[3;1\x1b(A";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Esc(intermediates, ignore, byte) => {
                assert_eq!(intermediates, b"(");
                assert_eq!(*byte, b'A');
                assert!(!ignore);
            },
            _ => panic!("expected esc sequence"),
        }
    }

    #[test]
    fn esc_reset_intermediates() {
        const INPUT: &[u8] = b"\x1b[?2004l\x1b#8";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 2);
        assert_eq!(dispatcher.dispatched[0], Sequence::Csi(vec![vec![2004]], vec![63], false, 'l'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Esc(vec![35], false, 56));
    }

    #[test]
    fn params_buffer_filled_with_subparam() {
        const INPUT: &[u8] = b"\x1b[::::::::::::::::::::::::::::::::x\x1b";
        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, intermediates, ignore, c) => {
                assert_eq!(intermediates, &[]);
                assert_eq!(params, &[[0; 32]]);
                assert_eq!(c, &'x');
                assert!(ignore);
            },
            _ => panic!("expected csi sequence"),
        }
    }

    #[cfg(not(feature = "std"))]
    #[test]
    fn build_with_fixed_size() {
        const INPUT: &[u8] = b"\x1b[3;1\x1b[?1049h";
        let mut dispatcher = Dispatcher::default();
        let mut parser: Parser<30> = Parser::new_with_size();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Csi(params, intermediates, ignore, _) => {
                assert_eq!(intermediates, b"?");
                assert_eq!(params, &[[1049]]);
                assert!(!ignore);
            },
            _ => panic!("expected csi sequence"),
        }
    }

    #[cfg(not(feature = "std"))]
    #[test]
    fn exceed_fixed_osc_buffer_size() {
        const OSC_BUFFER_SIZE: usize = 32;
        const NUM_BYTES: usize = OSC_BUFFER_SIZE + 100;
        const INPUT_START: &[u8] = b"\x1b]52;";
        const INPUT_END: &[u8] = b"\x07";

        let mut dispatcher = Dispatcher::default();
        let mut parser: Parser<OSC_BUFFER_SIZE> = Parser::new_with_size();

        // Create valid OSC escape
        parser.advance(&mut dispatcher, INPUT_START);

        // Exceed max buffer size
        parser.advance(&mut dispatcher, &[b'a'; NUM_BYTES]);

        // Terminate escape for dispatch
        parser.advance(&mut dispatcher, INPUT_END);

        assert_eq!(dispatcher.dispatched.len(), 1);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(params, _) => {
                assert_eq!(params.len(), 2);
                assert_eq!(params[0], b"52");
                assert_eq!(params[1].len(), OSC_BUFFER_SIZE - params[0].len());
                for item in params[1].iter() {
                    assert_eq!(*item, b'a');
                }
            },
            _ => panic!("expected osc sequence"),
        }
    }

    #[cfg(not(feature = "std"))]
    #[test]
    fn fixed_size_osc_containing_string_terminator() {
        const INPUT_START: &[u8] = b"\x1b]2;";
        const INPUT_MIDDLE: &[u8] = b"s\xe6\x9c\xab";
        const INPUT_END: &[u8] = b"\x1b\\";

        let mut dispatcher = Dispatcher::default();
        let mut parser: Parser<5> = Parser::new_with_size();

        parser.advance(&mut dispatcher, INPUT_START);
        parser.advance(&mut dispatcher, INPUT_MIDDLE);
        parser.advance(&mut dispatcher, INPUT_END);

        assert_eq!(dispatcher.dispatched.len(), 2);
        match &dispatcher.dispatched[0] {
            Sequence::Osc(params, false) => {
                assert_eq!(params[0], b"2");
                assert_eq!(params[1], INPUT_MIDDLE);
            },
            _ => panic!("expected osc sequence"),
        }
    }

    #[test]
    fn unicode() {
        const INPUT: &[u8] = b"\xF0\x9F\x8E\x89_\xF0\x9F\xA6\x80\xF0\x9F\xA6\x80_\xF0\x9F\x8E\x89";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 6);
        assert_eq!(dispatcher.dispatched[0], Sequence::Print('🎉'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Print('_'));
        assert_eq!(dispatcher.dispatched[2], Sequence::Print('🦀'));
        assert_eq!(dispatcher.dispatched[3], Sequence::Print('🦀'));
        assert_eq!(dispatcher.dispatched[4], Sequence::Print('_'));
        assert_eq!(dispatcher.dispatched[5], Sequence::Print('🎉'));
    }

    #[test]
    fn invalid_utf8() {
        const INPUT: &[u8] = b"a\xEF\xBCb";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 3);
        assert_eq!(dispatcher.dispatched[0], Sequence::Print('a'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Print('�'));
        assert_eq!(dispatcher.dispatched[2], Sequence::Print('b'));
    }

    #[test]
    fn partial_utf8() {
        const INPUT: &[u8] = b"\xF0\x9F\x9A\x80";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &INPUT[..1]);
        parser.advance(&mut dispatcher, &INPUT[1..2]);
        parser.advance(&mut dispatcher, &INPUT[2..3]);
        parser.advance(&mut dispatcher, &INPUT[3..]);

        assert_eq!(dispatcher.dispatched.len(), 1);
        assert_eq!(dispatcher.dispatched[0], Sequence::Print('🚀'));
    }

    #[test]
    fn partial_utf8_separating_utf8() {
        // This is different from the `partial_utf8` test since it has a multi-byte UTF8
        // character after the partial UTF8 state, causing a partial byte to be present
        // in the `partial_utf8` buffer after the 2-byte codepoint.

        // "ĸ🎉"
        const INPUT: &[u8] = b"\xC4\xB8\xF0\x9F\x8E\x89";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &INPUT[..1]);
        parser.advance(&mut dispatcher, &INPUT[1..]);

        assert_eq!(dispatcher.dispatched.len(), 2);
        assert_eq!(dispatcher.dispatched[0], Sequence::Print('ĸ'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Print('🎉'));
    }

    #[test]
    fn partial_invalid_utf8() {
        const INPUT: &[u8] = b"a\xEF\xBCb";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &INPUT[..1]);
        parser.advance(&mut dispatcher, &INPUT[1..2]);
        parser.advance(&mut dispatcher, &INPUT[2..3]);
        parser.advance(&mut dispatcher, &INPUT[3..]);

        assert_eq!(dispatcher.dispatched.len(), 3);
        assert_eq!(dispatcher.dispatched[0], Sequence::Print('a'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Print('�'));
        assert_eq!(dispatcher.dispatched[2], Sequence::Print('b'));
    }

    #[test]
    fn partial_invalid_utf8_split() {
        const INPUT: &[u8] = b"\xE4\xBF\x99\xB5";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, &INPUT[..2]);
        parser.advance(&mut dispatcher, &INPUT[2..]);

        assert_eq!(dispatcher.dispatched[0], Sequence::Print('俙'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Print('�'));
    }

    #[test]
    fn partial_utf8_into_esc() {
        const INPUT: &[u8] = b"\xD8\x1b012";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 4);
        assert_eq!(dispatcher.dispatched[0], Sequence::Print('�'));
        assert_eq!(dispatcher.dispatched[1], Sequence::Esc(Vec::new(), false, b'0'));
        assert_eq!(dispatcher.dispatched[2], Sequence::Print('1'));
        assert_eq!(dispatcher.dispatched[3], Sequence::Print('2'));
    }

    #[test]
    fn c1s() {
        const INPUT: &[u8] = b"\x00\x1f\x80\x90\x98\x9b\x9c\x9d\x9e\x9fa";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 11);
        assert_eq!(dispatcher.dispatched[0], Sequence::Execute(0));
        assert_eq!(dispatcher.dispatched[1], Sequence::Execute(31));
        assert_eq!(dispatcher.dispatched[2], Sequence::Execute(128));
        assert_eq!(dispatcher.dispatched[3], Sequence::Execute(144));
        assert_eq!(dispatcher.dispatched[4], Sequence::Execute(152));
        assert_eq!(dispatcher.dispatched[5], Sequence::Execute(155));
        assert_eq!(dispatcher.dispatched[6], Sequence::Execute(156));
        assert_eq!(dispatcher.dispatched[7], Sequence::Execute(157));
        assert_eq!(dispatcher.dispatched[8], Sequence::Execute(158));
        assert_eq!(dispatcher.dispatched[9], Sequence::Execute(159));
        assert_eq!(dispatcher.dispatched[10], Sequence::Print('a'));
    }

    #[test]
    fn execute_anywhere() {
        const INPUT: &[u8] = b"\x18\x1a";

        let mut dispatcher = Dispatcher::default();
        let mut parser = Parser::new();

        parser.advance(&mut dispatcher, INPUT);

        assert_eq!(dispatcher.dispatched.len(), 2);
        assert_eq!(dispatcher.dispatched[0], Sequence::Execute(0x18));
        assert_eq!(dispatcher.dispatched[1], Sequence::Execute(0x1A));
    }
}
#[cfg(all(test, feature = "std"))]
mod bounded_osc_tests {
    use super::*;
    #[derive(Default)]
    struct Sink {
        osc: Vec<Vec<Vec<u8>>>,
        text: String,
    }
    impl Perform for Sink {
        fn osc_dispatch(&mut self, params: &[&[u8]], _: bool) {
            self.osc.push(params.iter().map(|p| p.to_vec()).collect());
        }
        fn print(&mut self, c: char) {
            self.text.push(c);
        }
    }
    #[test]
    fn osc_limit_counts_separators_and_recovers() {
        for size in [8191, 8192, 8193] {
            for terminator in [b"\x07".as_slice(), b"\x1b\\", b"\x18", b"\x1a", b"\x1b[0m"] {
                for split in [1, 4096, 16384] {
                    let mut parser = Parser::new();
                    let mut sink = Sink::default();
                    let mut bytes = b"\x1b]0;".to_vec();
                    bytes.extend(std::iter::repeat(b'x').take(size - 2));
                    bytes.extend_from_slice(terminator);
                    bytes.extend_from_slice(b"\x1b]0;ok\x07text");
                    for part in bytes.chunks(split) {
                        parser.advance(&mut sink, part);
                    }
                    assert_eq!(sink.osc.len(), if size <= 8192 { 2 } else { 1 });
                    assert_eq!(sink.osc.last().unwrap(), &[b"0".to_vec(), b"ok".to_vec()]);
                    assert_eq!(sink.text, "text");
                    assert!(parser.osc_raw.capacity() <= 8192);
                }
            }
        }
        let mut parser = Parser::new();
        let mut sink = Sink::default();
        for _ in 0..8 {
            parser.advance(&mut sink, b"\x1b]");
            parser.advance(&mut sink, &vec![b';'; 100_000]);
            parser.advance(&mut sink, b"\x07");
        }
        assert!(sink.osc.is_empty());
        assert!(parser.osc_raw.capacity() <= 8192);
    }
}

// qsh: a UTF-8 sequence split between two `advance` calls must not change
// what is dispatched. Upstream 0.15.0 consumed the whole valid prefix of the
// partial buffer while printing only its first character, which dropped the
// character after a split sequence (alacritty/vte#159). It also printed a
// split C1 control (U+0080..=U+009F) that unsplit is executed
// (alacritty/vte#156).
#[cfg(test)]
mod split_utf8_tests {
    use std::vec::Vec;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Print(char),
        Execute(u8),
        Esc(Vec<u8>, bool, u8),
        Csi(Vec<Vec<u16>>, Vec<u8>, bool, char),
        Osc(Vec<Vec<u8>>, bool),
    }

    #[derive(Default)]
    struct Recorder(Vec<Event>);

    impl Perform for Recorder {
        fn print(&mut self, c: char) {
            self.0.push(Event::Print(c));
        }

        fn execute(&mut self, byte: u8) {
            self.0.push(Event::Execute(byte));
        }

        fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
            self.0.push(Event::Esc(intermediates.to_vec(), ignore, byte));
        }

        fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], ignore: bool, c: char) {
            let params = params.iter().map(|param| param.to_vec()).collect();
            self.0.push(Event::Csi(params, intermediates.to_vec(), ignore, c));
        }

        fn osc_dispatch(&mut self, params: &[&[u8]], bell_terminated: bool) {
            let params = params.iter().map(|param| param.to_vec()).collect();
            self.0.push(Event::Osc(params, bell_terminated));
        }
    }

    fn parse(parts: &[&[u8]]) -> Vec<Event> {
        let mut parser = Parser::new();
        let mut recorder = Recorder::default();
        for part in parts {
            parser.advance(&mut recorder, part);
        }
        recorder.0
    }

    /// Text in every UTF-8 length, combining marks, controls and escape
    /// sequences next to multi-byte text, and invalid or truncated input.
    const SAMPLES: &[&[u8]] = &[
        "B\u{301}C\u{2500}".as_bytes(),
        "ïcø".as_bytes(),
        "д п р".as_bytes(),
        "Съешь же ещё этих мягких булок, да выпей чаю.".as_bytes(),
        "e\u{301}h\u{300}z a\u{308}b\u{20dd}c".as_bytes(),
        "a界b😀c\u{fe0f}dĸ🎉x".as_bytes(),
        "é\r\né\tü\x07ß".as_bytes(),
        "д\x1b[31mп\x1b[0mр".as_bytes(),
        "д\x1b]0;ти тул\x07з\x1b]2;x\x1b\\ж".as_bytes(),
        "ä\x1b(Bö\x1b7ü".as_bytes(),
        b"a\xef\xbcb",
        b"\xe4\xbf\x99\xb5x",
        b"\xd8\x1b012",
        b"\xff a \xc3(b \xe2\x82 x \xf0\x9f\x98 y",
        b"\xc3\xa9 \xc3",
        "a\u{85}b\u{9b}c\u{80}\u{9f}d".as_bytes(),
        "ж\u{88}x\u{9c}з".as_bytes(),
    ];

    #[test]
    fn every_split_dispatches_what_one_advance_does() {
        for sample in SAMPLES {
            let whole = parse(&[sample]);
            for at in 0..=sample.len() {
                let (a, b) = sample.split_at(at);
                assert_eq!(parse(&[a, b]), whole, "{sample:x?} split at {at}");
            }
            for first in 0..=sample.len() {
                for second in first..=sample.len() {
                    let parts = [&sample[..first], &sample[first..second], &sample[second..]];
                    assert_eq!(parse(&parts), whole, "{sample:x?} split at {first}, {second}");
                }
            }
            let bytes: Vec<&[u8]> = sample.chunks(1).collect();
            assert_eq!(parse(&bytes), whole, "{sample:x?} byte by byte");
        }
    }

    #[test]
    fn the_character_after_a_split_sequence_is_dispatched() {
        // Upstream 0.15.0 dropped the 'h', the space and the 'c'.
        assert_eq!(
            parse(&[b"e\xcc", b"\x81h\xcc\x80z"]),
            ['e', '\u{301}', 'h', '\u{300}', 'z'].map(Event::Print)
        );
        assert_eq!(parse(&[b"\xd0", b"\xb4 \xd0\xbf"]), ['д', ' ', 'п'].map(Event::Print));
        assert_eq!(parse(&[b"\xc3", b"\xafc\xc3\xb8"]), ['ï', 'c', 'ø'].map(Event::Print));
    }

    #[test]
    fn a_split_c1_control_is_executed_as_unsplit() {
        for c1 in 0x80..=0x9f_u8 {
            let bytes = char::from(c1).encode_utf8(&mut [0; 4]).as_bytes().to_vec();
            let expected = [Event::Execute(c1)];
            assert_eq!(parse(&[&bytes]), expected);
            assert_eq!(parse(&[&bytes[..1], &bytes[1..]]), expected, "{c1:#x}");
            // Followed by more text, through the arm that sees a valid prefix.
            let mut more = bytes.clone();
            more.extend_from_slice("x\u{e9}".as_bytes());
            let expected = [Event::Execute(c1), Event::Print('x'), Event::Print('\u{e9}')];
            assert_eq!(parse(&[&more[..1], &more[1..]]), expected, "{c1:#x}");
        }
    }
}
