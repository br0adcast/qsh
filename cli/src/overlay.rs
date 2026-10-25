//! The frame the person sees: the shell's frame with the client's own chrome
//! -- the status line above it, or the plate over its top row, and a window
//! on top of both. Built on a copy, on the way to the renderer: none of it
//! ever enters the screen model (`ShellState`), which is the server's alone.

use terminal::{Cell, Frame, FLAG_WIDE, FLAG_WIDE_SPACER};

use crate::status;
use crate::window::Boxed;

/// `shell` as the terminal shows it. With `line`, one row taller: the line
/// on row 0, the shell's rows below it and its cursor one row down; the
/// modes, the mouse and the palette stay the shell's. Without it, `plate`
/// (when given) over the shell's top row. `boxed` goes on top of either, and
/// hides the cursor while it is there.
pub fn compose(
    shell: &Frame,
    line: Option<&[Cell]>,
    plate: Option<&str>,
    boxed: Option<&Boxed>,
) -> Frame {
    let shell = crate::viewport::project(
        shell,
        terminal_size::ViewportSize::new(
            shell.cols,
            terminal_size::MAX_VIEWPORT_ROWS - u16::from(line.is_some()),
        ),
    );
    finish_compose(shell, line, plate, boxed)
}

/// Compose chrome on an already-owned presentation frame without cloning its grid.
pub fn compose_owned(
    shell: Frame,
    line: Option<&[Cell]>,
    plate: Option<&str>,
    boxed: Option<&Boxed>,
) -> Frame {
    let size = terminal_size::ViewportSize::new(
        shell.cols,
        terminal_size::MAX_VIEWPORT_ROWS - u16::from(line.is_some()),
    );
    let shell = crate::viewport::project_owned(shell, size);
    finish_compose(shell, line, plate, boxed)
}

fn finish_compose(
    shell: Frame,
    line: Option<&[Cell]>,
    plate: Option<&str>,
    boxed: Option<&Boxed>,
) -> Frame {
    let mut out = match plate {
        Some(text) => status::overlay_owned(shell, text),
        None => shell,
    };
    if let Some(line) = line {
        let cols = usize::from(out.cols);
        let mut cells = Vec::with_capacity(cols + out.cells.len());
        cells.extend(line.iter().take(cols).cloned());
        cells.resize(cols, Cell::blank());
        cells.append(&mut out.cells);
        out.cells = cells;
        out.rows += 1;
        out.cursor_row += 1;
    }
    if let Some(boxed) = boxed {
        for cell in &mut out.cells {
            cell.flags |= terminal::FLAG_DIM;
        }
        paint_box(&mut out, boxed);
        out.cursor_visible = false;
    }
    let size = terminal_size::ViewportSize::new(out.cols, out.rows);
    crate::viewport::project_owned(out, size)
}

/// Puts `boxed`'s cells over `frame`, clipped at its edges. A wide glyph
/// cut by the box's edge would carry half of itself under the box and
/// shift the row, so the halves left outside become plain spaces.
fn paint_box(frame: &mut Frame, boxed: &Boxed) {
    let cols = usize::from(frame.cols);
    for (i, line) in boxed.lines.iter().enumerate() {
        let row = usize::from(boxed.top) + i;
        if row >= usize::from(frame.rows) {
            break;
        }
        let left = usize::from(boxed.left);
        let right = (left + line.len()).min(cols);
        if left >= right {
            continue;
        }
        let start = row * cols;
        for (col, cell) in (left..right).zip(line) {
            let mut cell = *cell;
            if (col + 1 == right && cell.flags & FLAG_WIDE != 0)
                || (col == left && cell.flags & FLAG_WIDE_SPACER != 0)
            {
                cell = Cell::blank();
            }
            frame.cells[start + col] = cell;
        }
        // The first half of a wide glyph just left of the box, its second
        // half now under it.
        if left > 0 && frame.cells[start + left - 1].flags & FLAG_WIDE != 0 {
            frame.cells[start + left - 1] = Cell {
                flags: terminal::FLAG_DIM,
                ..Cell::blank()
            };
        }
        // The second half of a wide glyph just right of the box, its first
        // half now under it.
        if right < cols && frame.cells[start + right].flags & FLAG_WIDE_SPACER != 0 {
            frame.cells[start + right] = Cell {
                flags: terminal::FLAG_DIM,
                ..Cell::blank()
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use terminal::{Cell, Frame};

    #[test]
    fn chrome_keeps_presentation_bounded_and_cannot_emit_half_a_glyph() {
        let shell = Frame::blank(65535, 65535);
        let out = compose(&shell, Some(&[]), None, None);
        assert_eq!((out.cols, out.rows, out.cells.len()), (512, 257, 512 * 257));
        let shell = Frame::blank(1, 1);
        let mut wide = Cell::blank();
        wide.ch = '界';
        wide.flags = FLAG_WIDE;
        let out = compose(&shell, Some(&[wide]), None, None);
        assert_eq!(out.cells[0], Cell::blank());
    }

    #[test]
    fn the_line_sits_above_the_shell_and_the_cursor_moves_with_it() {
        let mut shell = Frame::blank(4, 2);
        shell.cells[0].ch = 's';
        shell.cursor_row = 1;
        let line = vec![
            Cell {
                ch: 'L',
                ..Cell::blank()
            };
            4
        ];
        let f = compose(&shell, Some(&line), None, None);
        assert_eq!(f.rows, 3);
        assert_eq!(f.cell(0, 0).ch, 'L');
        assert_eq!(f.cell(1, 0).ch, 's');
        assert_eq!(f.cursor_row, 2);
    }

    #[test]
    fn a_box_goes_on_top_and_hides_the_cursor() {
        let shell = Frame::blank(6, 4);
        let b = crate::window::Boxed {
            top: 1,
            left: 2,
            lines: vec![vec![
                Cell {
                    ch: 'B',
                    ..Cell::blank()
                };
                2
            ]],
        };
        let f = compose(&shell, None, None, Some(&b));
        assert_eq!(f.cell(1, 2).ch, 'B');
        assert_eq!(f.cell(1, 3).ch, 'B');
        assert!(!f.cursor_visible);
    }

    #[test]
    fn a_window_dims_only_the_backdrop_and_preserves_the_source() {
        let mut shell = Frame::blank(8, 4);
        shell.cells.iter_mut().for_each(|c| c.ch = 'S');
        let boxed = Boxed {
            top: 1,
            left: 2,
            lines: vec![vec![Cell::blank(); 3]; 2],
        };
        let shown = compose(&shell, None, None, Some(&boxed));
        for row in 0..4 {
            for col in 0..8 {
                let inside = (1..3).contains(&row) && (2..5).contains(&col);
                assert_eq!(
                    shown.cell(row, col).flags & terminal::FLAG_DIM != 0,
                    !inside
                );
                assert_eq!(shell.cell(row, col).flags & terminal::FLAG_DIM, 0);
            }
        }
        assert!(compose(&shell, None, None, None)
            .cells
            .iter()
            .all(|c| c.flags & terminal::FLAG_DIM == 0));
    }
    #[test]
    fn owned_composition_preserves_each_original_neighbour_repair_pass() {
        let mut source = Frame::blank(4, 1);
        source.cells[0].flags = terminal::FLAG_LEADING_WIDE_SPACER | FLAG_WIDE;
        source.cells[1].flags = FLAG_WIDE | FLAG_WIDE_SPACER;
        source.cells[2].flags = FLAG_WIDE | FLAG_WIDE_SPACER;
        source.cells[3].ch = 'X';
        let saved = source.clone();
        for plate in [None, Some("")] {
            let borrowed = compose(&source, None, plate, None);
            let actual = compose_owned(source.clone(), None, plate, None);
            assert_eq!(actual, borrowed);
            assert_eq!(&actual.cells[..2], &[Cell::blank(), Cell::blank()]);
            assert_eq!(
                actual.cells[2],
                if plate.is_some() {
                    Cell::blank()
                } else {
                    source.cells[2]
                }
            );
            assert_eq!(actual.cells[3], source.cells[3]);
        }
        assert_eq!(source, saved);
    }
}
