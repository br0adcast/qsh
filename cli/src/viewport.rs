//! Bounded top-left projection from the logical shell to the physical display.
use terminal::{Cell, Frame, FLAG_LEADING_WIDE_SPACER, FLAG_WIDE, FLAG_WIDE_SPACER};
use terminal_size::ViewportSize;

/// Crop before adding chrome; a partial wide glyph is never printable.
pub fn project(frame: &Frame, size: ViewportSize) -> Frame {
    let mut out = frame.clone();
    out.cols = frame.cols.min(size.cols());
    out.rows = frame.rows.min(size.rows());
    out.cells.clear();
    for row in 0..out.rows {
        for col in 0..out.cols {
            let mut cell = *frame.cell(row, col);
            if cell.flags & FLAG_LEADING_WIDE_SPACER != 0
                || (cell.flags & FLAG_WIDE != 0 && col + 1 >= out.cols)
                || (cell.flags & FLAG_WIDE_SPACER != 0
                    && (col == 0 || frame.cell(row, col - 1).flags & FLAG_WIDE == 0))
            {
                cell = Cell::blank();
            }
            out.cells.push(cell);
        }
    }
    if out.cursor_col >= out.cols || out.cursor_row >= out.rows {
        out.cursor_visible = false;
        out.cursor_col = 0;
        out.cursor_row = 0;
    }
    out
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
