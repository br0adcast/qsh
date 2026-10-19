//! Bounded side effects for an explicitly authoritative fresh-output feed.

use alacritty_terminal::event::{Event, EventListener};
use std::sync::{Arc, Mutex};

/// Maximum reply bytes produced by one fresh-output feed, including a flush
/// of the parser's previously buffered synchronized update.
pub const MAX_TERMINAL_REPLY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReplyError {
    /// Required responses exceeded the collection bound; no prefix is returned.
    Overflow,
}

/// A passive repaint together with replies from flushing buffered fresh output.
#[derive(Debug)]
pub struct TerminalRepaint {
    pub bytes: Vec<u8>,
    pub replies: Vec<u8>,
}

#[derive(Default)]
struct Collection {
    active: bool,
    bytes: Vec<u8>,
    overflow: bool,
}

#[derive(Clone, Default)]
pub(crate) struct ReplyListener(Arc<Mutex<Collection>>);

impl ReplyListener {
    pub(crate) fn capture(&self) -> Capture {
        let mut collection = self.0.lock().unwrap();
        debug_assert!(!collection.active);
        collection.active = true;
        collection.overflow = false;
        collection.bytes.clear();
        Capture(self.clone())
    }
}

impl EventListener for ReplyListener {
    fn send_event(&self, event: Event) {
        let Event::PtyWrite(reply) = event else {
            // Physical pixels, clipboard and palette policy belong to a
            // consumer that actually owns them. Never retain their callbacks.
            return;
        };
        let mut collection = self.0.lock().unwrap();
        if !collection.active || collection.overflow {
            return;
        }
        if reply.len() > MAX_TERMINAL_REPLY_BYTES - collection.bytes.len() {
            collection.overflow = true;
            collection.bytes.clear();
            return;
        }
        let needed = collection.bytes.len() + reply.len();
        if needed > collection.bytes.capacity() {
            let capacity = needed
                .max(collection.bytes.capacity().saturating_mul(2))
                .min(MAX_TERMINAL_REPLY_BYTES);
            let additional = capacity - collection.bytes.len();
            collection.bytes.reserve_exact(additional);
        }
        collection.bytes.extend_from_slice(reply.as_bytes());
    }
}

/// Keep capture disabled outside its lexical feed, including unwinding.
pub(crate) struct Capture(ReplyListener);

impl Capture {
    pub(crate) fn finish(self) -> Result<Vec<u8>, TerminalReplyError> {
        let mut collection = self.0 .0.lock().unwrap();
        if collection.overflow {
            return Err(TerminalReplyError::Overflow);
        }
        // Do not carry spare collector capacity into a queue whose permit
        // accounts only the returned bytes. Item metadata is budgeted separately.
        Ok(std::mem::take(&mut collection.bytes)
            .into_boxed_slice()
            .into_vec())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let mut collection = self.0 .0.lock().unwrap_or_else(|error| error.into_inner());
        collection.active = false;
        collection.bytes.clear();
        collection.overflow = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TerminalCore;

    #[test]
    fn passive_model_does_not_allocate_or_retain_query_responses() {
        let mut term = TerminalCore::new(80, 24);
        term.feed(b"\x1b[c\x1b[5n\x1b[6n");
        let collection = term.replies.0.lock().unwrap();
        assert!(!collection.active);
        assert!(collection.bytes.is_empty());
        assert_eq!(collection.bytes.capacity(), 0);
    }

    #[test]
    fn unwinding_capture_discards_pending_replies_and_disables_the_listener() {
        let listener = ReplyListener::default();
        let _ = std::panic::catch_unwind(|| {
            let _capture = listener.capture();
            listener.send_event(Event::PtyWrite("answer".into()));
            panic!("owned test unwind");
        });
        listener.send_event(Event::PtyWrite("must stay silent".into()));
        let collection = listener.0.lock().unwrap();
        assert!(!collection.active);
        assert!(collection.bytes.is_empty());
        assert!(!collection.overflow);
    }
}
