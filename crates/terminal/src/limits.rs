//! Per-model history policy. This bounds logical cells, not allocator bytes.
use terminal_size::TerminalSize;

const MAX_HISTORY_LINES: usize = 10_000;
const MAX_HISTORY_CELLS: usize = 1_048_576;

/// Terminal construction policy applied before allocating the emulator.
#[derive(Debug, Clone, Copy)]
pub struct TerminalOptions {
    pub history_lines: usize,
    pub replay: bool,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            history_lines: MAX_HISTORY_LINES,
            replay: false,
        }
    }
}

pub(crate) fn effective_history(requested: usize, size: TerminalSize) -> usize {
    requested
        .min(MAX_HISTORY_LINES)
        .min(MAX_HISTORY_CELLS / usize::from(size.cols()))
}
