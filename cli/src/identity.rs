//! How an account or host name is shown where a person decides whether to
//! trust it: the first-use and changed-key questions for QSH and SSH, the
//! SSH recovery authorization and the qshd installation question.
//!
//! Two different names must never look the same there, so a character that
//! a terminal would draw as nothing, or that would rearrange what is drawn
//! around it, is shown as `\u{XXXX}` (its code point in hex, at least four
//! digits), and a backslash as `\\`. Every other character is shown as it
//! is: all scripts, combining marks and emoji. Only the presentation
//! changes; the name itself is used unchanged for the connection, the
//! known-hosts lookup and everything that is stored.
//!
//! A character is escaped when it is (rules apply in order):
//!
//! 1. a backslash, as `\\`;
//! 2. a joiner (Join_Control: ZWNJ, ZWJ), unless it joins: after a virama
//!    (Canonical_Combining_Class 9), as RFC 5892 appendix A allows both; a
//!    ZWNJ between a left- or dual-joining and a right- or dual-joining
//!    letter, transparent letters in between (also RFC 5892); or a ZWJ
//!    between two Extended_Pictographic characters, the first optionally
//!    followed by an emoji modifier or U+FE0F (an emoji ZWJ sequence);
//! 3. a variation selector (Variation_Selector), unless it selects a form
//!    of the character before it: U+FE0E or U+FE0F after a non-ASCII
//!    Emoji character, or after `0`-`9`, `#` or `*` in a keycap
//!    (U+20E3 follows); U+E0100..U+E01EF after a Unified_Ideograph;
//!    a Mongolian free variation selector after a Mongolian character;
//!    U+FE00..U+FE0D after a non-ASCII letter, number or symbol;
//! 4. a tag character (U+E0020..U+E007F), unless it is part of an emoji tag
//!    sequence: U+1F3F4, tags U+E0020..U+E007E, then U+E007F;
//! 5. a space (U+0020) at either end of the name;
//! 6. any other character that is a control (Cc), a line or paragraph
//!    separator (Zl, Zp), a format character (Cf) other than a visible
//!    Prepended_Concatenation_Mark, unassigned (Cn), private use (Co), a
//!    noncharacter, Bidi_Control, White_Space other than U+0020, or
//!    Default_Ignorable_Code_Point.
//!
//! Rule 6 covers the zero-width space, the word joiner and the invisible
//! operators, the byte order mark, the soft hyphen, the interlinear
//! annotation controls U+FFF9..U+FFFB (format characters that are not
//! Default_Ignorable), the Hangul fillers and the combining grapheme joiner,
//! and every terminal and direction control.
//!
//! The output is bounded: a name whose presentation would exceed
//! [`MAX_SHOWN`] bytes is cut at a character boundary and ends with how
//! many characters were left out and a SHA-256 prefix of the whole name, so
//! two long names that differ only in the part not shown still look
//! different. At most [`MAX_EXAMINED`] characters are examined.

use icu_properties::props::{
    BidiControl, CanonicalCombiningClass, DefaultIgnorableCodePoint, Emoji, EmojiModifier,
    ExtendedPictographic, GeneralCategory, GeneralCategoryGroup, JoinControl, JoiningType,
    NoncharacterCodePoint, PrependedConcatenationMark, Script, UnifiedIdeograph, VariationSelector,
    WhiteSpace,
};
use icu_properties::{CodePointMapData, CodePointSetData};
use sha2::{Digest, Sha256};

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
const BLACK_FLAG: char = '\u{1F3F4}';
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
        let suffix = format!("...[+{} characters, sha256 {hash}]", total - kept);
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
        return !in_flag_tag_sequence(chars, index);
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

/// Whether the variation selector at `index` selects a form of the
/// character before it (rule 3).
fn selects(chars: &[char], index: usize) -> bool {
    let Some(&base) = index.checked_sub(1).and_then(|i| chars.get(i)) else {
        return false;
    };
    let selector = chars[index];
    match u32::from(selector) {
        0xFE0E | 0xFE0F => {
            (!base.is_ascii() && CodePointSetData::new::<Emoji>().contains(base))
                || (matches!(base, '0'..='9' | '#' | '*') && chars.get(index + 1) == Some(&KEYCAP))
        }
        0xE0100..=0xE01EF => CodePointSetData::new::<UnifiedIdeograph>().contains(base),
        0x180B..=0x180D | 0x180F => {
            CodePointMapData::<Script>::new().get(base) == Script::Mongolian
        }
        0xFE00..=0xFE0D => {
            let category = CodePointMapData::<GeneralCategory>::new().get(base);
            !base.is_ascii()
                && GeneralCategoryGroup::Letter
                    .union(GeneralCategoryGroup::Number)
                    .union(GeneralCategoryGroup::Symbol)
                    .contains(category)
        }
        _ => false,
    }
}

fn is_tag(c: char) -> bool {
    ('\u{E0020}'..=CANCEL_TAG).contains(&c)
}

/// Whether the tag character at `index` is part of an emoji tag sequence
/// (rule 4).
fn in_flag_tag_sequence(chars: &[char], index: usize) -> bool {
    let spec = |c: &char| ('\u{E0020}'..='\u{E007E}').contains(c);
    let mut start = index;
    if chars[index] == CANCEL_TAG {
        // The cancel tag ends a sequence of at least one tag specification.
        if index == 0 || !spec(&chars[index - 1]) {
            return false;
        }
        start -= 1;
    }
    while start > 0 && spec(&chars[start - 1]) {
        start -= 1;
    }
    let mut end = index;
    while end < chars.len() && spec(&chars[end]) {
        end += 1;
    }
    start > 0 && chars[start - 1] == BLACK_FLAG && chars.get(end) == Some(&CANCEL_TAG)
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
            "葛\u{E0100}",
            "ᠠ\u{180B}",
            "∩\u{FE00}",
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
            ("0\u{FE00}", '\u{FE00}'),
            (" \u{FE00}x", '\u{FE00}'),
            ("中\u{FE0E}", '\u{FE0E}'),
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
        ] {
            let shown = shown(name);
            assert!(shown.escaped, "{name:?} -> {:?}", shown.text);
            assert_eq!(decode(&shown.text), name);
            assert!(!shown.text.chars().any(is_tag), "{:?}", shown.text);
        }
    }

    #[test]
    fn a_backslash_is_doubled_so_no_escape_can_be_forged() {
        let shown = shown("DOMAIN\\user");
        assert_eq!(shown.text, "DOMAIN\\\\user");
        assert!(!shown.escaped, "a backslash alone needs no note");
        assert_ne!(show("a\\u{200B}b"), show("a\u{200B}b"));
        assert_eq!(show("a\\u{200B}b"), "a\\\\u{200B}b");
    }

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
            assert!(shown.contains(" characters, sha256 "), "{shown:?}");
            assert!(!shown.ends_with('\\') || shown.ends_with(']'));
        }
        let one = format!("{}x", "a".repeat(5000));
        let other = format!("{}y", "a".repeat(5000));
        assert_ne!(show(&one), show(&other));
        let cut = show(&"a".repeat(MAX_SHOWN + 1));
        let omitted: usize = cut
            .split("...[+")
            .nth(1)
            .and_then(|tail| tail.split(' ').next())
            .and_then(|count| count.parse().ok())
            .expect("a count");
        assert_eq!(
            cut.split("...[+").next().unwrap().len() + omitted,
            MAX_SHOWN + 1
        );
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
