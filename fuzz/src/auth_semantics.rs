//! Independent expectations for a deliberately closed listing language.
use super::auth_keys::{key, MAX_INPUT, PUBLIC_LINE};
use sshauth::verify::key_is_listed;

fn decision(listing: &str, expected: bool) {
    assert!(listing.len() <= MAX_INPUT);
    assert_eq!(
        key_is_listed(listing, &key()).unwrap(),
        expected,
        "generated listing decision"
    );
}

const CLASSES: u8 = 12;
/// Emit a known line class and its independent decisive effect. No Entry parser
/// is used to calculate permission. Comments/other keys never decide it.
fn line(class: u8, comment: &str) -> (String, Option<bool>) {
    match class % CLASSES {
        0 => (format!("{PUBLIC_LINE} {comment}\n"), Some(true)),
        1 => (format!(" \t{PUBLIC_LINE}\r\n"), Some(true)),
        2 => (format!("restrict {PUBLIC_LINE}\n"), Some(false)),
        3 => (format!("command=\"echo ok\" {PUBLIC_LINE}\n"), Some(false)),
        4 => (format!("from=\"*.example.test\" {PUBLIC_LINE}\n"), Some(false)),
        5 => (format!("\u{a0}{PUBLIC_LINE}\n"), Some(false)),
        6 => (format!("\u{2003}{PUBLIC_LINE}\n"), Some(false)),
        7 => (format!("\x0b{PUBLIC_LINE}\n"), Some(false)),
        8 => (format!("\x0c{PUBLIC_LINE}\n"), Some(false)),
        9 => (format!("# {PUBLIC_LINE}\n"), None),
        10 => ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other\n".into(), None),
        _ => (format!("invalid-prefix {PUBLIC_LINE}\n"), Some(false)),
    }
}

pub(super) fn exercise(input: &[u8]) {
    // At most16 generated lines and32 safe ASCII comment characters.
    let comment: String = input
        .iter()
        .take(32)
        .map(|byte| char::from(b'a' + byte % 26))
        .collect();
    let mut listing = String::new();
    let mut expected = None;
    for &class in input.iter().take(16) {
        let (text, effect) = line(class, &comment);
        listing.push_str(&text);
        if expected.is_none() {
            expected = effect;
        }
    }
    decision(&listing, expected.unwrap_or(false));

    if let Ok(text) = std::str::from_utf8(input) {
        for (prefix, expected) in [
            (format!("{PUBLIC_LINE}\n"), true),
            (format!("restrict {PUBLIC_LINE}\n"), false),
        ] {
            // Keep the whole transformation within the reader-boundary cap;
            // the original raw text still receives the original property.
            let mut end = text.len().min(MAX_INPUT - prefix.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            decision(&format!("{prefix}{}", &text[..end]), expected);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[should_panic(expected = "generated listing decision")]
    fn oracle_detects_incorrect_authorization_expectation() {
        decision("", true);
    }
    #[test]
    fn every_line_class_and_first_decisive_order() {
        for a in 0..CLASSES {
            for b in 0..CLASSES {
                exercise(&[a, b]);
            }
        }
        decision(PUBLIC_LINE, true);
        decision(&format!("restrict {PUBLIC_LINE}\n{PUBLIC_LINE}"), false);
        decision(&format!("{PUBLIC_LINE}\nrestrict {PUBLIC_LINE}"), true);
        // No trailing comment: exercise the conservative malformed barrier.
        let bare = PUBLIC_LINE.rsplit_once(' ').unwrap().0;
        decision(&format!("restrict {bare}\n{PUBLIC_LINE}"), false);
        decision(
            &format!("command=\"echo # quoted\" {bare}\n{PUBLIC_LINE}"),
            false,
        );
    }
    #[test]
    fn bounded_generated_and_raw_prefix_properties() {
        exercise(&[]);
        exercise(&[255; MAX_INPUT]);
        exercise(&vec![b'x'; MAX_INPUT]);
        exercise("\u{a0}\u{2003}".repeat(1024).as_bytes());
    }
}
