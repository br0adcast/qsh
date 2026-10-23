#![forbid(unsafe_code)]

//! Validated logical terminal geometry and bounded physical viewport geometry.
//!
//! Network boundaries should use [`TerminalSize::new`] to reject invalid sizes.
//! Local display adapters can use [`TerminalSize::for_viewport`] to clamp them.

use std::fmt;

pub const MIN_TERMINAL_COLS: u16 = 2;
pub const MAX_TERMINAL_COLS: u16 = 512;
pub const MIN_TERMINAL_ROWS: u16 = 1;
pub const MAX_TERMINAL_ROWS: u16 = 256;
pub const MAX_TERMINAL_CELLS: usize = 131_072;
pub const MAX_VIEWPORT_COLS: u16 = MAX_TERMINAL_COLS;
/// Includes one chrome row above the logical terminal.
pub const MAX_VIEWPORT_ROWS: u16 = MAX_TERMINAL_ROWS + 1;

/// Logical geometry accepted by the terminal model and its peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TerminalSize {
    cols: u16,
    rows: u16,
}

impl TerminalSize {
    /// Reject geometry outside the logical terminal limits.
    pub fn new(cols: u16, rows: u16) -> Result<Self, SizeError> {
        let cells = usize::from(cols).checked_mul(usize::from(rows));
        if !(MIN_TERMINAL_COLS..=MAX_TERMINAL_COLS).contains(&cols)
            || !(MIN_TERMINAL_ROWS..=MAX_TERMINAL_ROWS).contains(&rows)
            || !matches!(cells, Some(cells) if cells <= MAX_TERMINAL_CELLS)
        {
            return Err(SizeError { cols, rows });
        }
        Ok(Self { cols, rows })
    }

    /// Adapt local physical dimensions to bounded logical terminal dimensions.
    pub fn for_viewport(cols: u16, rows: u16) -> Self {
        Self {
            cols: cols.clamp(MIN_TERMINAL_COLS, MAX_TERMINAL_COLS),
            rows: rows.clamp(MIN_TERMINAL_ROWS, MAX_TERMINAL_ROWS),
        }
    }

    pub fn cols(self) -> u16 {
        self.cols
    }

    pub fn rows(self) -> u16 {
        self.rows
    }

    pub fn cells(self) -> usize {
        usize::from(self.cols)
            .checked_mul(usize::from(self.rows))
            .expect("validated terminal dimensions fit usize")
    }
}

/// Physical display geometry, allowing empty displays and a chrome row.
///
/// Convert through [`TerminalSize::for_viewport`] before creating a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ViewportSize {
    cols: u16,
    rows: u16,
}

impl ViewportSize {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            cols: cols.min(MAX_VIEWPORT_COLS),
            rows: rows.min(MAX_VIEWPORT_ROWS),
        }
    }

    pub fn cols(self) -> u16 {
        self.cols
    }

    pub fn rows(self) -> u16 {
        self.rows
    }

    pub fn cells(self) -> usize {
        usize::from(self.cols)
            .checked_mul(usize::from(self.rows))
            .expect("bounded viewport dimensions fit usize")
    }
}

/// Invalid logical terminal dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeError {
    cols: u16,
    rows: u16,
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid terminal size {}x{}: expected {}..={} columns and {}..={} rows (at most {} cells)",
            self.cols, self.rows, MIN_TERMINAL_COLS, MAX_TERMINAL_COLS,
            MIN_TERMINAL_ROWS, MAX_TERMINAL_ROWS, MAX_TERMINAL_CELLS,
        )
    }
}

impl std::error::Error for SizeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_bounds_and_cell_counts() {
        for (cols, rows, cells) in [(2, 1, 2), (512, 256, 131_072)] {
            let size = TerminalSize::new(cols, rows).unwrap();
            assert_eq!(
                (size.cols(), size.rows(), size.cells()),
                (cols, rows, cells)
            );
        }
    }

    #[test]
    fn rejects_invalid_terminal_dimensions() {
        for (cols, rows) in [
            (1, 1),
            (0, 1),
            (2, 0),
            (513, 1),
            (2, 257),
            (u16::MAX, u16::MAX),
        ] {
            assert!(
                TerminalSize::new(cols, rows).is_err(),
                "accepted {cols}x{rows}"
            );
        }
    }

    #[test]
    fn local_terminal_adapter_clamps_both_dimensions() {
        for (cols, rows, expected) in [
            (1, 0, (2, 1)),
            (80, 24, (80, 24)),
            (u16::MAX, u16::MAX, (512, 256)),
        ] {
            let size = TerminalSize::for_viewport(cols, rows);
            assert_eq!((size.cols(), size.rows()), expected);
            assert_eq!(TerminalSize::new(size.cols(), size.rows()).unwrap(), size);
        }
    }

    #[test]
    fn viewport_preserves_small_dimensions_and_clamps_large_ones() {
        for (cols, rows, expected, cells) in [
            (1, 0, (1, 0), 0),
            (0, 257, (0, 257), 0),
            (80, 25, (80, 25), 2000),
            (u16::MAX, u16::MAX, (512, 257), 131_584),
        ] {
            let size = ViewportSize::new(cols, rows);
            assert_eq!((size.cols(), size.rows()), expected);
            assert_eq!(size.cells(), cells);
        }
    }

    #[test]
    fn size_error_implements_standard_error() {
        let error = TerminalSize::new(1, 1).unwrap_err();
        let standard: &dyn std::error::Error = &error;
        assert!(!standard.to_string().is_empty());
    }
}
