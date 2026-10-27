use super::*;
use std::cell::Cell as Counter;

thread_local! {
    static COMPARISONS: Counter<(usize, usize)> = const { Counter::new((0, 0)) };
}
pub(super) fn note_row() {
    COMPARISONS.with(|count| {
        let (rows, cells) = count.get();
        count.set((rows + 1, cells));
    });
}
pub(super) fn note_cell() {
    COMPARISONS.with(|count| {
        let (rows, cells) = count.get();
        count.set((rows, cells + 1));
    });
}

// The original detector is deliberately kept as an independent test oracle.
// Its predicate order and first accepted shift are the existing contract.
fn reference(previous: &Frame, frame: &Frame) -> Option<u16> {
    for lines in 1..frame.rows {
        let kept = frame.rows - lines;
        let confirmed = kept - 1;
        if confirmed == 0 {
            continue;
        }
        let moved = (0..confirmed).any(|row| !rows_equal(previous, frame, row, row));
        if !moved {
            continue;
        }
        let shifted = (0..confirmed).all(|row| rows_equal(previous, frame, row + lines, row));
        if !shifted {
            continue;
        }
        let corroborated = (0..confirmed).any(|row| !row_is_blank(frame, row));
        if corroborated {
            return Some(lines);
        }
    }
    None
}

fn bounded_prefix(cols: u16, rows: u16) {
    let mut before = Frame::blank(cols, rows);
    for cell in &mut before.cells {
        cell.ch = 'A';
    }
    let mut observations = Vec::new();
    for changed in [None, Some(rows - 1), Some(rows - 2)] {
        let mut after = before.clone();
        if let Some(row) = changed {
            after.cell_mut(row, cols - 1).ch = 'B';
        }
        COMPARISONS.with(|count| count.set((0, 0)));
        let result = scrolled_by(&before, &after);
        let work = COMPARISONS.with(Counter::get);
        observations.push((changed, result, work));
    }
    println!("{cols}x{rows} unchanged-prefix observations: {observations:?}");
    let trusted = usize::from(rows - 2);
    assert!(
        observations
            .iter()
            .all(|(_, result, work)| result.is_none()
                && *work == (trusted, trusted * usize::from(cols))),
        "{cols}x{rows} unchanged/bottom-only real row/cell comparisons: {observations:?}"
    );
}

#[test]
fn unchanged_prefix_comparisons_are_bounded_at_typical_geometry() {
    bounded_prefix(200, 50);
}
#[test]
fn unchanged_prefix_comparisons_are_bounded_at_maximum_geometry() {
    bounded_prefix(512, 257);
}

fn row_pattern(cols: u16, rows: u16, mut pattern: usize) -> Frame {
    let mut frame = Frame::blank(cols, rows);
    for row in 0..rows {
        let ch = [' ', 'A', 'B'][pattern % 3];
        pattern /= 3;
        for col in 0..cols {
            frame.cell_mut(row, col).ch = ch;
        }
    }
    frame
}

#[test]
fn detector_matches_original_for_exhaustive_small_repeated_row_patterns() {
    for rows in 0..=4 {
        let patterns = 3usize.pow(u32::from(rows));
        for cols in [0, 1, 4] {
            for previous in 0..patterns {
                for next in 0..patterns {
                    let a = row_pattern(cols, rows, previous);
                    let b = row_pattern(cols, rows, next);
                    assert_eq!(
                        scrolled_by(&a, &b),
                        reference(&a, &b),
                        "{cols}x{rows} patterns {previous} -> {next}"
                    );
                }
            }
        }
    }
}

#[test]
fn detector_matches_original_for_complete_cells_and_palette_variants() {
    let mut seed = 0x348c_0115_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for n in 0..1024 {
        let cols = [0, 1, 2, 8][n % 4];
        let rows = [0, 1, 2, 3, 4, 7, 12][n % 7];
        let mut a = Frame::blank(cols, rows);
        for cell in &mut a.cells {
            let bits = next();
            cell.ch = [' ', 'A', '界', '\0'][(bits % 4) as usize];
            cell.combining = terminal::CombiningMarks::from_slice(&['\u{301}', '\u{302}']);
            cell.flags = (bits >> 8) as u16;
            cell.fg = Color::Indexed(bits as u8);
            cell.bg = Color::Rgb((bits >> 16) as u32 & 0x00ff_ffff);
        }
        let mut b = a.clone();
        for cell in &mut b.cells {
            if next() % 3 == 0 {
                cell.ch = 'B';
                cell.flags ^= FLAG_WIDE;
            }
        }
        std::sync::Arc::make_mut(&mut b.palette).entries[n % 256] ^= 0x00ff_ffff;
        assert_eq!(scrolled_by(&a, &b), reference(&a, &b), "mixed case {n}");
    }
}

#[test]
fn ambiguous_shifts_keep_the_smallest_accepted_distance() {
    let mut a = Frame::blank(4, 6);
    let mut b = a.clone();
    for (row, (old, new)) in ['A', 'B', 'A', 'B', 'A', 'B']
        .into_iter()
        .zip(['B', 'A', 'B', 'A', 'B', 'C'])
        .enumerate()
    {
        for col in 0..4 {
            a.cell_mut(row as u16, col).ch = old;
            b.cell_mut(row as u16, col).ch = new;
        }
    }
    assert_eq!(reference(&a, &b), Some(1));
    assert_eq!(scrolled_by(&a, &b), Some(1));
}

#[test]
fn blank_erasure_and_insufficient_evidence_keep_original_results() {
    for rows in [0, 1, 2, 3, 8] {
        let mut a = Frame::blank(4, rows);
        if rows > 0 {
            a.cell_mut(0, 0).ch = 'A';
        }
        let b = Frame::blank(4, rows);
        assert_eq!(scrolled_by(&a, &b), reference(&a, &b));
        assert_eq!(scrolled_by(&a, &b), None);
    }
}
