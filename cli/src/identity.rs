//! How an account or host name is shown where a person decides whether to
//! trust it: the first-use and changed-key questions for QSH and SSH, the
//! SSH recovery authorization and the qshd installation question.
//!
//! Two different names must not be shown as the same text there. A
//! character that is invisible on its own, or that rearranges the text
//! around it, is shown as `\u{XXXX}` (its code point in hex, at least four
//! digits), and a backslash as `\\`, so the shown text decodes to exactly
//! one name. Every other character is shown as it is: all scripts,
//! combining marks and emoji. This is a property of the text written to the
//! terminal; how it is drawn still depends on the terminal and its fonts.
//! Only the presentation changes; the name itself is used unchanged for the
//! connection, the known-hosts lookup and everything that is stored.
//!
//! A character is escaped when it is (rules apply in order):
//!
//! 1. a backslash, as `\\`;
//! 2. a joiner (Join_Control: ZWNJ, ZWJ), unless it is in a joining
//!    context: after a virama (Canonical_Combining_Class 9), as RFC 5892
//!    appendix A allows both; a ZWNJ between a left- or dual-joining and a
//!    right- or dual-joining letter, transparent letters in between (also
//!    RFC 5892); or a ZWJ between two Extended_Pictographic characters, the
//!    first optionally followed by an emoji modifier or U+FE0F (an emoji
//!    ZWJ sequence);
//! 3. a variation selector (Variation_Selector), unless it forms a
//!    registered variation sequence with the character before it: one of
//!    StandardizedVariants.txt or emoji-variation-sequences.txt, where an
//!    emoji sequence on `0`-`9`, `#` or `*` counts only in a keycap
//!    (U+20E3 follows). Ideographic variation sequences (U+E0100..U+E01EF)
//!    are registered in the Ideographic Variation Database, which is not
//!    included, so they are escaped;
//! 4. a tag character (U+E0020..U+E007F), unless it is part of an RGI
//!    emoji tag sequence (emoji-sequences.txt: the flags of England,
//!    Scotland and Wales);
//! 5. a space (U+0020) at either end of the name;
//! 6. any other character that is a control (Cc), a line or paragraph
//!    separator (Zl, Zp), a format character (Cf) other than a
//!    Prepended_Concatenation_Mark, unassigned (Cn), private use (Co), a
//!    noncharacter, Bidi_Control, White_Space other than U+0020, or
//!    Default_Ignorable_Code_Point.
//!
//! Rule 6 covers the zero-width space, the word joiner and the invisible
//! operators, the byte order mark, the soft hyphen, the interlinear
//! annotation controls U+FFF9..U+FFFB (format characters that are not
//! Default_Ignorable), the Hangul fillers and the combining grapheme joiner,
//! and every terminal and direction control. The sequence tables are
//! generated from Unicode 17.0.0 by `scripts/generate_identity_sequences.py`
//! into `identity_sequences.rs`.
//!
//! The output is bounded: a name whose presentation would exceed
//! [`MAX_SHOWN`] bytes is cut between characters and ends with
//! `\[+N more characters, sha256 H]`, where H is the first 64 bits of the
//! SHA-256 of the whole name. A backslash followed by `[` cannot come from
//! a name, since its backslashes are doubled, so a cut presentation never
//! equals the presentation of another name that was not cut; H is a digest
//! discriminator between long names that agree in the part shown, not a
//! guarantee that they look different. At most [`MAX_EXAMINED`] characters
//! are examined.

use icu_properties::props::{
    BidiControl, CanonicalCombiningClass, DefaultIgnorableCodePoint, EmojiModifier,
    ExtendedPictographic, GeneralCategory, GeneralCategoryGroup, JoinControl, JoiningType,
    NoncharacterCodePoint, PrependedConcatenationMark, VariationSelector, WhiteSpace,
};
use icu_properties::{CodePointMapData, CodePointSetData};
use sha2::{Digest, Sha256};

use crate::identity_sequences::{TAG_SEQUENCES, VARIATION_SEQUENCES};

/// The most bytes one name's presentation takes, its truncation note
/// included.
pub const MAX_SHOWN: usize = 512;

/// The most characters of one name that are examined; the rest are only
/// counted and hashed.
pub const MAX_EXAMINED: usize = 1024;

/// The line a question adds below the names when any of them shows an
/// escaped character.
pub const NOTE: &str = "(\\u{...} stands for a character that is invisible or changes the \
     layout of the text around it; the name is used exactly as it is, not as shown)";

const ZWNJ: char = '\u{200C}';
const ZWJ: char = '\u{200D}';
const VS16: char = '\u{FE0F}';
const KEYCAP: char = '\u{20E3}';
const CANCEL_TAG: char = '\u{E007F}';

/// A name as shown in a trust question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub text: String,
    /// Whether any character other than a backslash was escaped.
    pub escaped: bool,
}

/// `name` as it is shown in a trust question.
pub fn show(name: &str) -> String {
    shown(name).text
}

/// The note for a question showing `names`, if any of them needs it.
pub fn note(names: &[&str]) -> Option<&'static str> {
    names.iter().any(|name| shown(name).escaped).then_some(NOTE)
}

/// `question`, with [`NOTE`] on a line of its own before its last line
/// when any of `names` shows an escaped character.
pub fn with_note(question: String, names: &[&str]) -> String {
    let Some(note) = note(names) else {
        return question;
    };
    match question.rsplit_once('\n') {
        Some((body, last)) => format!("{body}\n{note}\n{last}"),
        None => format!("{note}\n{question}"),
    }
}

/// `name` as it is shown, and whether anything in it was escaped.
pub fn shown(name: &str) -> Shown {
    let chars: Vec<char> = name.chars().take(MAX_EXAMINED).collect();
    let mut pieces = Vec::with_capacity(chars.len());
    let mut escaped = false;
    for index in 0..chars.len() {
        let c = chars[index];
        let piece = if c == '\\' {
            "\\\\".to_string()
        } else if hidden(&chars, index) {
            escaped = true;
            format!("\\u{{{:04X}}}", u32::from(c))
        } else {
            c.to_string()
        };
        pieces.push(piece);
    }
    let whole: usize = pieces.iter().map(String::len).sum();
    if chars.len() == name.chars().count() && whole <= MAX_SHOWN {
        return Shown {
            text: pieces.concat(),
            escaped,
        };
    }
    let total = name.chars().count();
    let digest = Sha256::digest(name.as_bytes());
    let hash: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    let mut text = String::new();
    let mut kept = 0;
    loop {
        let suffix = format!("\\[+{} more characters, sha256 {hash}]", total - kept);
        match pieces.get(kept) {
            Some(piece) if text.len() + piece.len() + suffix.len() <= MAX_SHOWN => {
                text.push_str(piece);
                kept += 1;
            }
            _ => {
                text.push_str(&suffix);
                return Shown { text, escaped };
            }
        }
    }
}

/// Whether `chars[index]` is shown escaped (backslashes aside).
fn hidden(chars: &[char], index: usize) -> bool {
    let c = chars[index];
    if CodePointSetData::new::<JoinControl>().contains(c) {
        return !joins(chars, index);
    }
    if CodePointSetData::new::<VariationSelector>().contains(c) {
        return !selects(chars, index);
    }
    if is_tag(c) {
        return !in_tag_sequence(chars, index);
    }
    if c == ' ' {
        return index == 0 || index + 1 == chars.len();
    }
    let category = CodePointMapData::<GeneralCategory>::new().get(c);
    if category == GeneralCategory::Format {
        return !CodePointSetData::new::<PrependedConcatenationMark>().contains(c);
    }
    let invisible = GeneralCategoryGroup::Control
        .union(GeneralCategoryGroup::LineSeparator)
        .union(GeneralCategoryGroup::ParagraphSeparator)
        .union(GeneralCategoryGroup::Unassigned)
        .union(GeneralCategoryGroup::PrivateUse)
        .union(GeneralCategoryGroup::Surrogate);
    invisible.contains(category)
        || CodePointSetData::new::<NoncharacterCodePoint>().contains(c)
        || CodePointSetData::new::<BidiControl>().contains(c)
        || CodePointSetData::new::<WhiteSpace>().contains(c)
        || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
}

/// Whether the joiner at `index` joins what is around it (rule 2).
fn joins(chars: &[char], index: usize) -> bool {
    let Some(&before) = index.checked_sub(1).and_then(|i| chars.get(i)) else {
        return false;
    };
    if CodePointMapData::<CanonicalCombiningClass>::new().get(before)
        == CanonicalCombiningClass::Virama
    {
        return true;
    }
    match chars[index] {
        ZWNJ => {
            let joining = CodePointMapData::<JoiningType>::new();
            let left = chars[..index]
                .iter()
                .rev()
                .find(|c| joining.get(**c) != JoiningType::Transparent);
            let right = chars[index + 1..]
                .iter()
                .find(|c| joining.get(**c) != JoiningType::Transparent);
            left.is_some_and(|c| {
                matches!(
                    joining.get(*c),
                    JoiningType::LeftJoining | JoiningType::DualJoining
                )
            }) && right.is_some_and(|c| {
                matches!(
                    joining.get(*c),
                    JoiningType::RightJoining | JoiningType::DualJoining
                )
            })
        }
        ZWJ => {
            let pictographic = CodePointSetData::new::<ExtendedPictographic>();
            let modifier = CodePointSetData::new::<EmojiModifier>();
            let mut base = index;
            while base > 0 && (chars[base - 1] == VS16 || modifier.contains(chars[base - 1])) {
                base -= 1;
            }
            base > 0
                && pictographic.contains(chars[base - 1])
                && chars
                    .get(index + 1)
                    .is_some_and(|c| pictographic.contains(*c))
        }
        _ => false,
    }
}

/// Whether the variation selector at `index` forms a registered variation
/// sequence with the character before it (rule 3).
fn selects(chars: &[char], index: usize) -> bool {
    let Some(&base) = index.checked_sub(1).and_then(|i| chars.get(i)) else {
        return false;
    };
    let selector = chars[index];
    if VARIATION_SEQUENCES
        .binary_search(&(u32::from(base), u32::from(selector)))
        .is_err()
    {
        return false;
    }
    // On an ASCII base, an emoji or text presentation selector draws like
    // the base itself outside a keycap.
    !(matches!(selector, '\u{FE0E}' | VS16) && base.is_ascii())
        || chars.get(index + 1) == Some(&KEYCAP)
}

fn is_tag(c: char) -> bool {
    ('\u{E0020}'..=CANCEL_TAG).contains(&c)
}

/// Whether the tag character at `index` is inside an RGI emoji tag
/// sequence (rule 4).
fn in_tag_sequence(chars: &[char], index: usize) -> bool {
    TAG_SEQUENCES.iter().any(|sequence| {
        (index.saturating_sub(sequence.len() - 1)..=index).any(|start| {
            chars
                .get(start..start + sequence.len())
                .is_some_and(|window| {
                    window
                        .iter()
                        .zip(sequence.iter())
                        .all(|(c, point)| u32::from(*c) == *point)
                })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escaped(c: char) -> String {
        format!("\\u{{{:04X}}}", u32::from(c))
    }

    /// The inverse of [`show`] for a name that was not cut short.
    fn decode(shown: &str) -> String {
        let mut out = String::new();
        let mut rest = shown;
        while let Some(at) = rest.find('\\') {
            out.push_str(&rest[..at]);
            rest = &rest[at..];
            if let Some(after) = rest.strip_prefix("\\\\") {
                out.push('\\');
                rest = after;
            } else {
                let after = rest.strip_prefix("\\u{").expect("an escape");
                let close = after.find('}').expect("a closed escape");
                let code = u32::from_str_radix(&after[..close], 16).expect("hex");
                out.push(char::from_u32(code).expect("a scalar"));
                rest = &after[close + 1..];
            }
        }
        out.push_str(rest);
        out
    }

    fn assert_kept(name: &str) {
        let shown = shown(name);
        assert_eq!(shown.text, name, "{name:?} must be shown as it is");
        assert!(!shown.escaped, "{name:?} needs no note");
    }

    fn assert_escaped_at(name: &str, c: char) {
        let shown = shown(name);
        assert!(
            shown.text.contains(&escaped(c)),
            "{:04X} in {name:?} must be escaped, got {:?}",
            u32::from(c),
            shown.text
        );
        assert!(shown.escaped);
        assert_eq!(decode(&shown.text), name);
    }

    #[test]
    fn invisible_and_layout_characters_are_escaped_between_letters() {
        let cases = [
            // Zero-width and other format characters (Cf).
            '\u{200B}',
            '\u{2060}',
            '\u{2061}',
            '\u{2062}',
            '\u{2063}',
            '\u{2064}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{180E}',
            '\u{206A}',
            '\u{206F}',
            '\u{E0001}',
            '\u{1D173}',
            '\u{1BCA0}',
            '\u{13430}',
            // Interlinear annotation controls: format, not Default_Ignorable.
            '\u{FFF9}',
            '\u{FFFA}',
            '\u{FFFB}',
            // Default_Ignorable letters and marks.
            '\u{115F}',
            '\u{1160}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{034F}',
            '\u{17B4}',
            '\u{17B5}',
            // Unassigned Default_Ignorable code points.
            '\u{2065}',
            '\u{FFF0}',
            '\u{E0080}',
            // Spaces other than U+0020.
            '\u{00A0}',
            '\u{1680}',
            '\u{2000}',
            '\u{200A}',
            '\u{202F}',
            '\u{205F}',
            '\u{3000}',
            // Terminal controls, separators and Bidi_Control.
            '\0',
            '\t',
            '\n',
            '\r',
            '\x1b',
            '\x7f',
            '\u{85}',
            '\u{9b}',
            '\u{2028}',
            '\u{2029}',
            '\u{061C}',
            '\u{200E}',
            '\u{200F}',
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            // Unassigned, private use and noncharacters.
            '\u{0378}',
            '\u{E000}',
            '\u{F0000}',
            '\u{FDD0}',
            '\u{FFFE}',
            '\u{10FFFF}',
        ];
        for c in cases {
            let name = format!("exa{c}mple");
            assert_escaped_at(&name, c);
            assert_eq!(show(&name), format!("exa{}mple", escaped(c)));
            assert_ne!(show(&name), show("example"), "{:04X}", u32::from(c));
        }
    }

    #[test]
    fn confusable_names_look_different() {
        let pairs = [
            ("example.com", "exa\u{200B}mple.com"),
            ("root", "ro\u{FEFF}ot"),
            ("admin", "ad\u{FFF9}min\u{FFFA}root\u{FFFB}"),
            ("paypal.com", "pay\u{200D}pal.com"),
            ("paypal.com", "pa\u{FE0F}ypal.com"),
            ("alice", "alice\u{3164}"),
            ("alice", "alice "),
            ("alice", " alice"),
            ("host.example", "host\u{202E}elpmaxe."),
            ("bob", "b\u{00AD}ob"),
        ];
        for (plain, disguised) in pairs {
            assert_kept(plain);
            assert_ne!(show(plain), show(disguised), "{disguised:?}");
            assert_eq!(decode(&show(disguised)), disguised);
            assert_eq!(note(&[plain, disguised]), Some(NOTE));
        }
    }

    #[test]
    fn multilingual_names_and_emoji_are_shown_as_they_are() {
        for name in [
            "العربية",
            "עברית",
            "Кириллица",
            "中文",
            "日本語のテキスト",
            "한국어",
            "ไทย",
            "e\u{301}cole",
            "می\u{200C}روم",
            "क्\u{200D}ष",
            "क्\u{200C}ष",
            "ക്\u{200D}",
            "👩\u{200D}💻",
            "👩🏽\u{200D}💻",
            "❤\u{FE0F}\u{200D}🔥",
            "🏳\u{FE0F}\u{200D}🌈",
            "❤\u{FE0F}",
            "☺\u{FE0E}",
            "1\u{FE0F}\u{20E3}",
            "#\u{FE0F}\u{20E3}",
            "🇺🇦",
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
            "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
            "🏴\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}x",
            "ᠠ\u{180B}",
            "∩\u{FE00}",
            "0\u{FE00}",
            "≨\u{FE00}",
            "丽\u{FE00}",
            "\u{0600}١٢٣",
            "a b",
            "alice.o'neil",
        ] {
            assert_kept(name);
        }
    }

    #[test]
    fn joiners_are_escaped_where_they_join_nothing() {
        for name in [
            "a\u{200D}b",
            "a\u{200C}b",
            "\u{200D}a",
            "a\u{200D}",
            "\u{200C}",
            "👩\u{200D}a",
            "a\u{200D}💻",
            "👩\u{200D}\u{200D}💻",
            "ш\u{200C}л",
            "ש\u{200C}ל",
            "م\u{200C}a",
            "a\u{200C}م",
        ] {
            let c = if name.contains('\u{200D}') {
                '\u{200D}'
            } else {
                '\u{200C}'
            };
            assert_escaped_at(name, c);
        }
        // A doubled joiner joins neither neighbour: both are shown.
        assert_eq!(
            show("👩\u{200D}\u{200D}💻"),
            format!("👩{0}{0}💻", escaped('\u{200D}'))
        );
        // Only the joiner that joins nothing is escaped; the emoji ZWJ
        // sequence after it stays intact.
        assert_eq!(
            show("a\u{200D}👩\u{200D}💻"),
            format!("a{}👩\u{200D}💻", escaped('\u{200D}'))
        );
    }

    #[test]
    fn variation_selectors_are_escaped_where_they_select_nothing() {
        for (name, selector) in [
            ("a\u{FE0F}", '\u{FE0F}'),
            ("a\u{FE0E}", '\u{FE0E}'),
            ("1\u{FE0F}", '\u{FE0F}'),
            ("\u{FE0F}", '\u{FE0F}'),
            ("❤\u{FE0F}\u{FE0F}", '\u{FE0F}'),
            ("a\u{E0100}", '\u{E0100}'),
            ("a\u{180B}", '\u{180B}'),
            (" \u{FE00}x", '\u{FE00}'),
            ("中\u{FE0E}", '\u{FE0E}'),
            // Not registered: a selector with no defined sequence.
            ("é\u{FE00}", '\u{FE00}'),
            ("∩\u{FE01}", '\u{FE01}'),
            ("ᠠ\u{180F}", '\u{180F}'),
            ("≤\u{FE00}", '\u{FE00}'),
            // Ideographic variation sequences are registered in the IVD,
            // which is not included.
            ("葛\u{E0100}", '\u{E0100}'),
        ] {
            assert_escaped_at(name, selector);
        }
        assert_eq!(
            show("❤\u{FE0F}\u{FE0F}"),
            format!("❤\u{FE0F}{}", escaped('\u{FE0F}'))
        );
    }

    #[test]
    fn tags_are_escaped_outside_a_flag_sequence() {
        for name in [
            "a\u{E0067}\u{E0062}\u{E007F}",
            "🏴\u{E0067}\u{E0062}",
            "🏴\u{E007F}",
            "\u{E007F}",
            "a\u{E0041}b",
            // TAG SPACE is no part of a tag specification.
            "🏴\u{E0020}\u{E007F}",
            // Well formed but not RGI: California, and capital letters.
            "🏴\u{E0075}\u{E0073}\u{E0063}\u{E0061}\u{E007F}",
            "🏴\u{E0047}\u{E0042}\u{E0053}\u{E0043}\u{E0054}\u{E007F}",
            // Overlong, doubled and cut short.
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E0074}\u{E007F}",
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}\u{E007F}",
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E007F}",
            "\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
        ] {
            let shown = shown(name);
            assert!(shown.escaped, "{name:?} -> {:?}", shown.text);
            assert_eq!(decode(&shown.text), name);
            // A doubled cancel tag leaves the flag itself intact.
            if !name.ends_with("\u{E007F}\u{E007F}") {
                assert!(!shown.text.chars().any(is_tag), "{:?}", shown.text);
            }
        }
        assert_eq!(
            show("🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}\u{E007F}"),
            format!(
                "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}{}",
                escaped(CANCEL_TAG)
            )
        );
    }

    #[test]
    fn the_sequence_tables_are_sorted_and_hold_the_registered_entries() {
        assert!(VARIATION_SEQUENCES.windows(2).all(|pair| pair[0] < pair[1]));
        for registered in [
            (0x0030, 0xFE00),
            (0x2229, 0xFE00),
            (0x1820, 0x180B),
            (0x2764, 0xFE0F),
            (0x263A, 0xFE0E),
            (0x0023, 0xFE0F),
        ] {
            assert!(
                VARIATION_SEQUENCES.binary_search(&registered).is_ok(),
                "{registered:X?}"
            );
        }
        for unregistered in [(0x00E9, 0xFE00), (0x0061, 0xFE0F), (0x845B, 0xE0100)] {
            assert!(VARIATION_SEQUENCES.binary_search(&unregistered).is_err());
        }
        assert_eq!(TAG_SEQUENCES.len(), 3);
        assert!(TAG_SEQUENCES.iter().all(
            |sequence| sequence.first() == Some(&0x1F3F4) && sequence.last() == Some(&0xE007F)
        ));
    }

    #[test]
    fn a_backslash_is_doubled_so_no_escape_can_be_forged() {
        let shown = shown("DOMAIN\\user");
        assert_eq!(shown.text, "DOMAIN\\\\user");
        assert!(!shown.escaped, "a backslash alone needs no note");
        assert_ne!(show("a\\u{200B}b"), show("a\u{200B}b"));
        assert_eq!(show("a\\u{200B}b"), "a\\\\u{200B}b");
    }

    /// Distinct names give distinct text: this is about the encoded
    /// strings, not about how a terminal draws them.
    #[test]
    fn the_presentation_is_unambiguous_and_keeps_the_terminal_safe() {
        let alphabet = [
            'a',
            'Z',
            '0',
            '1',
            '#',
            ' ',
            '\\',
            'u',
            '{',
            '}',
            'ш',
            'م',
            'ک',
            'क',
            '्',
            '\u{301}',
            '👩',
            '💻',
            '❤',
            '🏴',
            '\u{1F3FD}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{FE0F}',
            '\u{FE0E}',
            '\u{20E3}',
            '\u{E0067}',
            '\u{E007F}',
            '\u{FFF9}',
            '\u{202E}',
            '\u{2028}',
            '\x1b',
            '\n',
            '\u{9b}',
            '\u{3164}',
            '\u{00A0}',
            '\u{E0100}',
            '中',
        ];
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let mut seen = std::collections::HashMap::new();
        for _ in 0..20_000 {
            let length = next(8);
            let name: String = (0..length)
                .map(|_| alphabet[next(alphabet.len())])
                .collect();
            let shown = show(&name);
            assert_eq!(decode(&shown), name, "{name:?} -> {shown:?}");
            if let Some(other) = seen.insert(shown.clone(), name.clone()) {
                assert_eq!(other, name, "two names shown as {shown:?}");
            }
            let bidi = CodePointSetData::new::<BidiControl>();
            assert!(
                !shown.chars().any(|c| c.is_control()
                    || matches!(c, '\u{2028}' | '\u{2029}')
                    || bidi.contains(c)
                    || c == '\u{200B}'),
                "{name:?} -> {shown:?}"
            );
        }
    }

    #[test]
    fn long_names_are_bounded_and_stay_distinct() {
        let fits = "a".repeat(MAX_SHOWN);
        assert_eq!(show(&fits), fits);
        for long in [
            "a".repeat(MAX_SHOWN + 1),
            "a".repeat(100_000),
            "\u{200B}".repeat(100_000),
            "中".repeat(MAX_SHOWN),
            "\\".repeat(MAX_SHOWN),
        ] {
            let shown = show(&long);
            assert!(shown.len() <= MAX_SHOWN, "{} bytes", shown.len());
            assert!(shown.contains(" more characters, sha256 "), "{shown:?}");
            assert!(shown.ends_with(']'));
        }
        let one = format!("{}x", "a".repeat(5000));
        let other = format!("{}y", "a".repeat(5000));
        assert_ne!(show(&one), show(&other));
        let cut = show(&"a".repeat(MAX_SHOWN + 1));
        let (kept, marker) = cut.split_once("\\[+").expect("a marker");
        let omitted: usize = marker
            .split(' ')
            .next()
            .and_then(|count| count.parse().ok())
            .expect("a count");
        assert_eq!(kept.len() + omitted, MAX_SHOWN + 1);
    }

    /// The review's example: a name written as a cut presentation is not
    /// shown as that presentation.
    #[test]
    fn a_name_cannot_look_like_a_cut_name() {
        for long in [
            "a".repeat(MAX_SHOWN + 1),
            "\u{200B}".repeat(4000),
            "ш".repeat(MAX_SHOWN),
        ] {
            let cut = show(&long);
            assert!(cut.len() <= MAX_SHOWN);
            assert_ne!(show(&cut), cut);
            // Nor is a name whose shown part decodes to the same text,
            // followed by the marker written literally.
            let (kept, marker) = cut.split_once("\\[+").expect("a marker");
            let forged = format!("{}\\[+{marker}", decode(kept));
            assert_ne!(show(&forged), cut, "{forged:?}");
        }
    }

    #[test]
    fn a_question_notes_escapes_once_before_its_last_line() {
        assert_eq!(note(&["host.example", "alice"]), None);
        assert_eq!(
            with_note("Host x\nTrust it?".into(), &["host.example"]),
            "Host x\nTrust it?"
        );
        assert_eq!(
            with_note("Host x\nTrust it?".into(), &["ho\u{200B}st", "a\u{200B}"]),
            format!("Host x\n{NOTE}\nTrust it?")
        );
        assert!(NOTE.is_ascii());
    }
}
