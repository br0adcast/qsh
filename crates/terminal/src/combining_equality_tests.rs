//! `CombiningMarks` equality compares the length and the occupied marks.
//! That equals the old comparison of the whole array only while every slot
//! past the length is `'\0'`. These tests check that invariant after every
//! way a suffix is built or changed, and check the new equality against the
//! old one on targeted and generated pairs.

use super::*;

/// The comparison `CombiningMarks` derived before: every slot, used or not,
/// and the length.
fn full_array_eq(a: &CombiningMarks, b: &CombiningMarks) -> bool {
    a.chars == b.chars && a.len == b.len
}

fn assert_tail_clear(marks: &CombiningMarks) {
    let len = usize::from(marks.len);
    assert!(len <= MAX_COMBINING_MARKS, "{marks:?}");
    assert!(
        marks.chars[len..].iter().all(|&slot| slot == '\0'),
        "{marks:?}"
    );
}

/// Both comparisons agree, in both directions, and equality means the same
/// visible suffix.
fn check_pair(a: &CombiningMarks, b: &CombiningMarks) {
    assert_tail_clear(a);
    assert_tail_clear(b);
    let expected = full_array_eq(a, b);
    assert_eq!(a == b, expected, "{a:?} vs {b:?}");
    assert_eq!(b == a, expected, "{b:?} vs {a:?}");
    assert_eq!(a.as_slice() == b.as_slice(), expected, "{a:?} vs {b:?}");
}

/// Zero-width scalars `push` accepts.
const VALID: [char; 6] = [
    '\u{301}', '\u{302}', '\u{308}', '\u{20dd}', '\u{200d}', '\u{fe0f}',
];

/// Scalars `push` rejects: controls, NUL among them, and scalars with a
/// width.
const INVALID: [char; 6] = ['\0', '\u{7}', '\u{1b}', 'a', '界', '\u{7f}'];

#[test]
fn every_construction_and_mutation_leaves_the_unused_slots_clear() {
    assert_tail_clear(&CombiningMarks::default());
    assert_tail_clear(&Cell::blank().combining);
    for mark in INVALID {
        let mut marks = CombiningMarks::default();
        assert!(!marks.push(mark), "{mark:?}");
        assert_eq!(marks, CombiningMarks::default());
        assert!(full_array_eq(&marks, &CombiningMarks::default()));
    }

    let mut marks = CombiningMarks::default();
    for n in 0..MAX_COMBINING_MARKS + 4 {
        let accepted = marks.push(VALID[n % VALID.len()]);
        assert_eq!(accepted, n < MAX_COMBINING_MARKS);
        assert!(!marks.push(INVALID[n % INVALID.len()]));
        assert_tail_clear(&marks);
        let copy = marks;
        assert_tail_clear(&copy);
        assert!(full_array_eq(&copy, &marks));
    }
    assert_eq!(marks.as_slice().len(), MAX_COMBINING_MARKS);

    let overflowing: Vec<char> = VALID.iter().copied().cycle().take(40).collect();
    let saturated = CombiningMarks::from_slice(&overflowing);
    assert_tail_clear(&saturated);
    assert_eq!(saturated.as_slice(), &overflowing[..MAX_COMBINING_MARKS]);

    let mut cell = Cell::blank();
    cell.combining = saturated;
    cell.set_char('x');
    assert_tail_clear(&cell.combining);
    assert!(cell.combining.is_empty());

    // The emulator builds every frame cell's suffix from what it stored,
    // including more marks than fit, invalid scalars between marks, and
    // marks replaced by later text.
    let mut t = TerminalCore::new(12, 4);
    t.feed("e\u{301}\u{302}\u{303} 界\u{304} 😀\u{fe0f}\r\n".as_bytes());
    t.feed(format!("a{}\r\n", "\u{301}".repeat(40)).as_bytes());
    t.feed("o\u{308}\u{7}\u{308}\x1b[8mh\u{301}\x1b[0m\r\n".as_bytes());
    t.feed("b\u{301}\u{302}\x1b[1;1Hz".as_bytes());
    let frame = t.frame();
    for cell in &frame.cells {
        assert_tail_clear(&cell.combining);
    }
    assert_eq!(frame.cells[0].ch, 'z');
    assert!(frame.cells[0].combining.is_empty());
    assert_eq!(
        frame.cells[12].combining.as_slice().len(),
        MAX_COMBINING_MARKS
    );
}

/// A suffix of `len` marks, chosen so that each position holds a mark the
/// neighbouring positions do not.
fn suffix(len: usize, seed: usize) -> CombiningMarks {
    let marks: Vec<char> = (0..len).map(|n| VALID[(n + seed) % VALID.len()]).collect();
    CombiningMarks::from_slice(&marks)
}

#[test]
fn equality_matches_the_full_array_for_every_length_and_position() {
    for len in 0..=MAX_COMBINING_MARKS {
        let base = suffix(len, 0);
        assert_eq!(base.as_slice().len(), len);
        check_pair(&base, &base);
        check_pair(&base, &suffix(len, 0));
        // Every occupied position differing on its own, the last included.
        for position in 0..len {
            let mut changed: Vec<char> = base.as_slice().to_vec();
            changed[position] = if changed[position] == '\u{301}' {
                '\u{302}'
            } else {
                '\u{301}'
            };
            let other = CombiningMarks::from_slice(&changed);
            assert_ne!(base, other, "length {len}, position {position}");
            check_pair(&base, &other);
        }
        // Every other length, shorter and longer, sharing the prefix.
        for other_len in 0..=MAX_COMBINING_MARKS {
            let other = suffix(other_len, 0);
            assert_eq!(base == other, len == other_len);
            check_pair(&base, &other);
        }
        // Rejected input changes nothing, at any length.
        let mut rejected = base;
        for mark in INVALID {
            rejected.push(mark);
        }
        assert_eq!(rejected, base);
        check_pair(&rejected, &base);
        // Overflow keeps the first sixteen marks.
        let mut full = base;
        while full.push('\u{20dd}') {}
        let mut overflowed = full;
        assert!(!overflowed.push('\u{301}'));
        assert_eq!(overflowed, full);
        check_pair(&overflowed, &full);
        check_pair(&overflowed, &base);
    }
}

/// xorshift64: a fixed, dependency-free sequence, so every run checks the
/// same cases.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    /// A scalar from a small pool, valid and invalid alike, so that
    /// generated suffixes often share prefixes and collide.
    fn scalar(&mut self) -> char {
        if self.below(4) == 0 {
            INVALID[self.below(INVALID.len())]
        } else {
            VALID[self.below(3)]
        }
    }
}

#[test]
fn generated_suffixes_compare_as_the_full_array_does() {
    let mut generator = Generator(0x9e37_79b9_7f4a_7c15);
    let mut built = Vec::new();
    for _ in 0..600 {
        let input: Vec<char> = (0..generator.below(MAX_COMBINING_MARKS + 8))
            .map(|_| generator.scalar())
            .collect();
        let mut pushed = CombiningMarks::default();
        let mut accepted = Vec::new();
        for &mark in &input {
            let fits = accepted.len() < MAX_COMBINING_MARKS;
            let valid = VALID.contains(&mark);
            assert_eq!(pushed.push(mark), fits && valid, "{mark:?}");
            if fits && valid {
                accepted.push(mark);
            }
        }
        let sliced = CombiningMarks::from_slice(&input);
        assert_eq!(pushed.as_slice(), accepted.as_slice());
        check_pair(&pushed, &sliced);
        assert_eq!(pushed, sliced);
        built.push(pushed);
    }
    let mut equal = 0;
    for a in &built {
        for b in &built {
            check_pair(a, b);
            equal += usize::from(a == b);
        }
    }
    // Beyond each suffix equal to itself, the pool makes some collide, so
    // both outcomes are exercised.
    assert!(equal > built.len(), "{equal}");
}

#[test]
fn cell_and_frame_equality_keep_every_other_field() {
    let mut cell = Cell::blank();
    cell.ch = 'e';
    cell.combining = suffix(MAX_COMBINING_MARKS, 0);
    cell.fg = Color::Indexed(3);
    cell.bg = Color::Rgb(0x102030);
    cell.flags = FLAG_HIDDEN | FLAG_BOLD;
    let same = cell;
    assert_eq!(cell, same);

    let mut last_mark = cell;
    let mut marks = suffix(MAX_COMBINING_MARKS - 1, 0).as_slice().to_vec();
    marks.push('\u{30a}');
    last_mark.combining = CombiningMarks::from_slice(&marks);
    assert_ne!(cell.combining.as_slice().last(), Some(&'\u{30a}'));
    let variants = [
        Cell { ch: 'f', ..cell },
        last_mark,
        Cell {
            combining: suffix(MAX_COMBINING_MARKS - 1, 0),
            ..cell
        },
        Cell {
            fg: Color::Indexed(4),
            ..cell
        },
        Cell {
            bg: Color::Default,
            ..cell
        },
        Cell {
            flags: FLAG_BOLD,
            ..cell
        },
        Cell {
            flags: FLAG_HIDDEN | FLAG_BOLD | FLAG_WIDE,
            ..cell
        },
    ];
    for variant in variants {
        assert_ne!(cell, variant, "{variant:?}");
    }
    // Text-only matching ignores colors and attributes, never marks.
    assert!(cell.contents_match(&variants[3]));
    assert!(!cell.contents_match(&last_mark));

    let mut t = TerminalCore::new(6, 2);
    t.feed(format!("\x1b[8;31m界{}", "\u{301}".repeat(MAX_COMBINING_MARKS)).as_bytes());
    let frame = t.frame();
    let mut changed = t.frame();
    assert_eq!(frame, changed);
    changed.cells[0] = Cell {
        combining: last_mark.combining,
        ..changed.cells[0]
    };
    assert_ne!(frame, changed);
    let mut moved = t.frame();
    moved.cursor_col += 1;
    assert_ne!(frame, moved);
    let mut recolored = t.frame();
    Arc::make_mut(&mut recolored.palette).entries[1] = 0x010101;
    assert_ne!(frame, recolored);
}
