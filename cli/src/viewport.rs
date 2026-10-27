//! Bounded top-left projection from the logical shell to the physical display.
use terminal::{Cell, Frame, FLAG_LEADING_WIDE_SPACER, FLAG_WIDE, FLAG_WIDE_SPACER};
use terminal_size::ViewportSize;

// Enumerate every field: adding Frame metadata must prompt an explicit review.
fn metadata(frame: &Frame, cols: u16, rows: u16, cells: Vec<Cell>) -> Frame {
    Frame {
        cols,
        rows,
        cells,
        cursor_col: frame.cursor_col,
        cursor_row: frame.cursor_row,
        cursor_visible: frame.cursor_visible,
        app_cursor: frame.app_cursor,
        app_keypad: frame.app_keypad,
        origin_mode: frame.origin_mode,
        mouse_tracking: frame.mouse_tracking,
        mouse_sgr: frame.mouse_sgr,
        bracketed_paste: frame.bracketed_paste,
        alt_screen: frame.alt_screen,
        palette: std::sync::Arc::clone(&frame.palette),
    }
}

fn repaired(cell: Cell, previous_flags: u16, col: u16, cols: u16) -> Cell {
    if cell.flags & FLAG_LEADING_WIDE_SPACER != 0
        || (cell.flags & FLAG_WIDE != 0 && col + 1 >= cols)
        || (cell.flags & FLAG_WIDE_SPACER != 0 && (col == 0 || previous_flags & FLAG_WIDE == 0))
    {
        Cell::blank()
    } else {
        cell
    }
}

fn clip_cursor(frame: &mut Frame, cols: u16, rows: u16) {
    if frame.cursor_col >= cols || frame.cursor_row >= rows {
        frame.cursor_visible = false;
        frame.cursor_col = 0;
        frame.cursor_row = 0;
    }
}

/// Crop before adding chrome; a partial wide glyph is never printable.
pub fn project(frame: &Frame, size: ViewportSize) -> Frame {
    let cols = frame.cols.min(size.cols());
    let rows = frame.rows.min(size.rows());
    let mut cells = Vec::with_capacity(usize::from(cols) * usize::from(rows));
    for row in 0..rows {
        let mut previous_flags = 0;
        for col in 0..cols {
            let cell = *frame.cell(row, col);
            cells.push(repaired(cell, previous_flags, col, cols));
            previous_flags = cell.flags;
        }
    }
    let mut out = metadata(frame, cols, rows, cells);
    clip_cursor(&mut out, cols, rows);
    out
}

/// Fill the bounded physical presentation area without reflowing the shell.
/// Cursor clipping uses the cropped grid, so padding never reveals a cursor.
pub fn project_padded(frame: &Frame, size: ViewportSize) -> Frame {
    let mut out = metadata(frame, size.cols(), size.rows(), Vec::new());
    project_padded_into(frame, size, &mut out);
    out
}

/// [`project_padded`] written into `out`, reusing its cell storage. Every
/// field of `out` is replaced, so nothing it held before survives.
pub fn project_padded_into(frame: &Frame, size: ViewportSize, out: &mut Frame) {
    let cols = frame.cols.min(size.cols());
    let rows = frame.rows.min(size.rows());
    let needed = usize::from(size.cols()) * usize::from(size.rows());
    let mut cells = std::mem::take(&mut out.cells);
    terminal::fit_cells(&mut cells, needed);
    cells.resize(needed, Cell::blank());
    *out = metadata(frame, size.cols(), size.rows(), cells);
    clip_cursor(out, cols, rows);
    for row in 0..rows {
        let mut previous_flags = 0;
        for col in 0..cols {
            let cell = *frame.cell(row, col);
            *out.cell_mut(row, col) = repaired(cell, previous_flags, col, cols);
            previous_flags = cell.flags;
        }
    }
}

/// Apply the same crop/repair pass to storage already owned by presentation.
/// Read each original cell before compacting; repaired neighbours are not input.
pub(crate) fn project_owned(mut frame: Frame, size: ViewportSize) -> Frame {
    let old_cols = usize::from(frame.cols);
    let cols = frame.cols.min(size.cols());
    let rows = frame.rows.min(size.rows());
    for row in 0..rows {
        let mut previous_flags = 0;
        for col in 0..cols {
            let source = usize::from(row) * old_cols + usize::from(col);
            let target = usize::from(row) * usize::from(cols) + usize::from(col);
            let cell = frame.cells[source];
            frame.cells[target] = repaired(cell, previous_flags, col, cols);
            previous_flags = cell.flags;
        }
    }
    frame.cells.truncate(usize::from(cols) * usize::from(rows));
    frame.cols = cols;
    frame.rows = rows;
    clip_cursor(&mut frame, cols, rows);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_blanks_orphan_spacers_and_hides_clipped_rows() {
        let mut frame = Frame::blank(3, 2);
        frame.cells[0].flags = FLAG_WIDE_SPACER;
        frame.cells[1].ch = 'x';
        frame.cells[2].flags = FLAG_LEADING_WIDE_SPACER;
        frame.cursor_row = 1;
        let projected = project(&frame, ViewportSize::new(3, 1));
        assert_eq!(
            projected.cells,
            vec![Cell::blank(), frame.cells[1], Cell::blank()]
        );
        assert!(!projected.cursor_visible);
        assert_eq!((projected.cursor_col, projected.cursor_row), (0, 0));
        let empty = project(&frame, ViewportSize::new(0, 0));
        assert!(empty.cells.is_empty());
        assert!(!empty.cursor_visible);
    }

    #[test]
    fn a_complete_wide_pair_and_modes_survive_projection() {
        let mut frame = Frame::blank(3, 2);
        frame.cells[0].ch = '界';
        frame.cells[0].flags = FLAG_WIDE;
        frame.cells[1].flags = FLAG_WIDE_SPACER;
        frame.mouse_sgr = true;
        frame.bracketed_paste = true;
        let projected = project(&frame, ViewportSize::new(2, 1));
        assert_eq!(&projected.cells, &frame.cells[..2]);
        assert!(projected.mouse_sgr && projected.bracketed_paste && projected.cursor_visible);
    }
}

#[cfg(test)]
mod complete_cell_tests {
    use super::*;
    #[test]
    fn complete_cell_projection_preserves_or_removes_entire_cluster() {
        let mut source = terminal::TerminalCore::new(12, 2);
        source.feed("e\u{301}界\u{302}".as_bytes());
        let source = source.frame();
        let intact = project(&source, ViewportSize::new(3, 2));
        assert_eq!(intact.cells[0], source.cells[0]);
        assert_eq!(intact.cells[1], source.cells[1]);
        let clipped = project(&source, ViewportSize::new(2, 2));
        assert_eq!(clipped.cells[0], source.cells[0]);
        assert_eq!(clipped.cells[1], Cell::blank());
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::sync::Arc;
    use terminal::{Color, MouseTracking, TerminalCore, FLAG_HIDDEN};

    #[test]
    fn padding_and_clipping_preserve_complete_metadata_and_cells() {
        let mut core = TerminalCore::new(4, 2);
        core.feed("e\u{301}界\u{302}x".as_bytes());
        let mut source = core.frame();
        source.cursor_col = 3;
        source.cursor_row = 1;
        source.cursor_visible = true;
        source.app_cursor = true;
        source.app_keypad = true;
        source.origin_mode = true;
        source.mouse_tracking = MouseTracking::Drag;
        source.mouse_sgr = true;
        source.bracketed_paste = true;
        source.alt_screen = true;
        source.cells[0].flags |= FLAG_HIDDEN;
        source.cells[0].fg = Color::Indexed(7);
        source.cells[0].bg = Color::Rgb(0x123456);
        Arc::make_mut(&mut source.palette).default_bg = 0x123456;
        let saved = source.clone();
        let padded = project_padded(&source, ViewportSize::new(6, 3));
        let mut expected = source.clone();
        expected.cols = 6;
        expected.rows = 3;
        expected.cells = vec![Cell::blank(); 18];
        expected.cells[..4].copy_from_slice(&source.cells[..4]);
        expected.cells[6..10].copy_from_slice(&source.cells[4..8]);
        assert_eq!(padded, expected);
        assert!(Arc::ptr_eq(&padded.palette, &source.palette));
        let clipped = project_padded(&source, ViewportSize::new(2, 3));
        expected.cols = 2;
        expected.cells = vec![
            source.cells[0],
            Cell::blank(),
            source.cells[4],
            source.cells[5],
            Cell::blank(),
            Cell::blank(),
        ];
        expected.cursor_visible = false;
        expected.cursor_col = 0;
        expected.cursor_row = 0;
        assert_eq!(clipped, expected);
        assert_eq!(source, saved);
    }

    #[test]
    fn repair_reads_original_neighbours_and_preserves_pass_order() {
        let mut source = Frame::blank(3, 1);
        source.cells[0].flags = FLAG_LEADING_WIDE_SPACER | FLAG_WIDE;
        source.cells[1].flags = FLAG_WIDE_SPACER;
        let once = project(&source, ViewportSize::new(3, 1));
        assert_eq!(once.cells[0], Cell::blank());
        assert_eq!(once.cells[1], source.cells[1]);
        let twice = project(&once, ViewportSize::new(3, 1));
        assert_eq!(twice.cells[1], Cell::blank());
    }
    #[test]
    fn owned_crop_preserves_storage_and_the_borrowed_single_pass_result() {
        let mut source = Frame::blank(7, 3);
        source.cells[0].flags = FLAG_LEADING_WIDE_SPACER | FLAG_WIDE;
        source.cells[1].flags = FLAG_WIDE_SPACER;
        source.cursor_col = 6;
        source.cursor_row = 2;
        for size in [
            ViewportSize::new(7, 3),
            ViewportSize::new(3, 2),
            ViewportSize::new(0, 0),
        ] {
            let owned = source.clone();
            let pointer = owned.cells.as_ptr();
            let capacity = owned.cells.capacity();
            let expected = project(&source, size);
            let actual = project_owned(owned, size);
            assert_eq!(actual, expected);
            assert_eq!(
                (actual.cells.as_ptr(), actual.cells.capacity()),
                (pointer, capacity)
            );
        }
    }
}
