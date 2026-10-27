//! Cell comparison work probe.
//!
//! Builds two frames from the same emulator input and compares them cell
//! by cell, the way the renderer diffs rows, a fixed number of times. It is
//! a measurement procedure, not a test: run it under a counter of executed
//! instructions or of `memcmp`/`bcmp` calls to see how much work the
//! comparisons take. The method and recorded results are in
//! docs/performance-baseline.md, under "Combining-mark equality".
//!
//!   cargo run --release -p terminal --example cell_equality -- CASE [ROUNDS]
//!
//! It prints the number of equal cell pairs it found, so a build that
//! compared differently would print a different count.

use std::hint::black_box;

use terminal::{Frame, TerminalCore};

const COLS: u16 = 200;
const ROWS: u16 = 50;

/// A full screen of text whose every cell carries `marks` combining marks,
/// starting each base character at `first`. Each cell is fed on its own:
/// vte 0.15 can drop a character after a UTF-8 sequence split between two
/// feeds, and no cell's bytes are split this way.
fn screen(marks: usize, first: u8) -> Frame {
    let mut t = TerminalCore::new(COLS, ROWS);
    for row in 0..ROWS {
        t.feed(format!("\x1b[{};1H", row + 1).as_bytes());
        for col in 0..COLS {
            let base = first + ((usize::from(row) + usize::from(col)) % 26) as u8;
            let mut cell = String::from(char::from(base));
            for mark in 0..marks {
                let offset = ((usize::from(col) + mark) % 0x30) as u32;
                cell.push(char::from_u32(0x0300 + offset).expect("combining mark"));
            }
            t.feed(cell.as_bytes());
        }
    }
    let frame = t.frame();
    assert!(frame
        .cells
        .iter()
        .all(|cell| cell.combining.as_slice().len() == marks));
    frame
}

fn main() {
    let mut args = std::env::args().skip(1);
    let case = args.next().unwrap_or_default();
    let rounds: usize = args.next().map_or(200, |n| n.parse().expect("rounds"));
    let (a, b) = match case.as_str() {
        // Equal frames: every comparison reads the whole cell.
        "empty" => (screen(0, b'a'), screen(0, b'a')),
        "short" => (screen(4, b'a'), screen(4, b'a')),
        "full" => (screen(16, b'a'), screen(16, b'a')),
        // The negative control: every base character differs, so each
        // comparison stops before the marks, whatever they hold.
        "base-differs" => (screen(16, b'a'), screen(16, b'A')),
        _ => {
            eprintln!("usage: cell_equality empty|short|full|base-differs [ROUNDS]");
            std::process::exit(2);
        }
    };
    let mut equal = 0usize;
    for _ in 0..rounds {
        let (a, b) = (black_box(&a), black_box(&b));
        equal += a.cells.iter().zip(&b.cells).filter(|(x, y)| x == y).count();
    }
    println!(
        "{{\"case\":\"{case}\",\"rounds\":{rounds},\"cells\":{},\"equal_pairs\":{equal}}}",
        a.cells.len()
    );
}
