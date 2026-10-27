//! Output split anywhere between `feed` calls, or by `feed`'s own chunking,
//! must leave the same screen as the unsplit output. A UTF-8 sequence split
//! this way once dropped the character after it (#354).

use super::*;

/// Cyrillic words with spaces, combining marks followed by ASCII, wide and
/// four-byte characters, and attributes between multi-byte characters.
const SAMPLES: &[&str] = &[
    "д п р",
    "Съешь же ещё этих мягких булок, да выпей чаю.",
    "e\u{301}h\u{300}z a\u{308}b\u{20dd}c",
    "a界b😀c\u{fe0f}d",
    "д\x1b[1;31mп\x1b[0m р\r\nё ж",
];

fn fed(parts: &[&[u8]]) -> Frame {
    let mut t = TerminalCore::new(48, 3);
    for part in parts {
        t.feed(part);
    }
    t.frame()
}

#[test]
fn a_split_between_feeds_leaves_the_unsplit_screen() {
    for sample in SAMPLES {
        let bytes = sample.as_bytes();
        let whole = fed(&[bytes]);
        for at in 0..=bytes.len() {
            let (a, b) = bytes.split_at(at);
            assert_eq!(fed(&[a, b]), whole, "{sample:?} split at {at}");
        }
    }
    // The case that lost the base character 'h' and gave its mark to 'e'.
    let split = fed(&[b"e\xcc", b"\x81h\xcc\x80z"]);
    assert_eq!(split.cells[1].ch, 'h');
    assert_eq!(split.cells[1].combining.as_slice(), &['\u{300}']);
}

#[test]
fn a_split_at_the_internal_chunk_boundary_leaves_the_unsplit_screen() {
    for sample in SAMPLES {
        let text = sample.as_bytes();
        for lead in 0..text.len() {
            // A prefix that ends the first 4,096-byte chunk at byte `lead`
            // of the sample: dots that stop at the margin, then a return.
            let prefix = 4095 - lead;
            let mut bytes = b"\x1b[?7l".to_vec();
            bytes.resize(prefix - 1, b'.');
            bytes.push(b'\r');
            bytes.extend_from_slice(text);

            let mut single = TerminalCore::new(48, 3);
            single.feed(&bytes);
            // The same bytes, fed so that no sequence is split.
            let mut unsplit = TerminalCore::new(48, 3);
            unsplit.feed(&bytes[..prefix]);
            unsplit.feed(text);
            assert_eq!(single.frame(), unsplit.frame(), "{sample:?} at {lead}");
        }
    }
}
